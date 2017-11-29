/*
 * Copyright 2017 WSO2.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.identity.sso.agent.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;

import com.nimbusds.jwt.SignedJWT;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.RequestDispatcher;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.json.JSONObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.w3c.dom.Element;
import org.wso2.carbon.identity.sso.agent.bean.LoggedInSessionBean;
import org.wso2.carbon.identity.sso.agent.bean.SSOAgentConfig;
import org.wso2.carbon.identity.sso.agent.exception.SSOAgentException;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentConstants;

/**
 *
 * @author chiran
 */
public class OIDCManager {

    private static Logger logger = Logger.getLogger(OIDCManager.class.getName());

    private SSOAgentConfig ssoAgentConfig = null;

    public OIDCManager(SSOAgentConfig ssoAgentConfig) {
        this.ssoAgentConfig = ssoAgentConfig;
    }

    public String doOIDCLogin(HttpServletRequest request, HttpServletResponse response) throws SSOAgentException {

        LoggedInSessionBean sessionBean = new LoggedInSessionBean();
        String hashOfSessionId = generateMD5Hash(request.getSession(false).getId());

        logger.log(Level.INFO, String.format("Login request via OIDC agent from client IP: %s", request.getRemoteAddr()));
        sessionBean.setOIDC(sessionBean.new OIDC());
        request.getSession().setAttribute(SSOAgentConstants.SESSION_BEAN_NAME, sessionBean);
        //using hash value of the sessionId as the nonce 
        request.getSession().setAttribute("hashOfSessionId", hashOfSessionId);

        try {
            OAuthClientRequest authzRequest = OAuthClientRequest
                    .authorizationLocation(ssoAgentConfig.getOIDC().getAuthzEndpoint())
                    .setClientId(ssoAgentConfig.getOIDC().getClientId())
                    .setRedirectURI(ssoAgentConfig.getOIDC().getCallBackUrl())
                    .setResponseType(ssoAgentConfig.getOIDC().getAuthzGrantType())
                    .setScope(ssoAgentConfig.getOIDC().getScope())
                    .setParameter("nonce", hashOfSessionId)
                    .buildQueryMessage();

            logger.log(Level.INFO, String.format("Sending the authorization Request to obtain Authorization_Code with follwing params: %s", authzRequest.getBody()));
            return authzRequest.getLocationUri();

        } catch (OAuthSystemException e) {
            throw new SSOAgentException("Error occured while building authentication request for client:"
                    + ssoAgentConfig.getOIDC().getClientId(), e);
        }
    }

    public void processCodeResponse(HttpServletRequest request, HttpServletResponse response) throws SSOAgentException {

        Boolean validIDToken = true;
        LoggedInSessionBean loggedInSessionBean = (LoggedInSessionBean) request.getSession().
                getAttribute(SSOAgentConstants.SESSION_BEAN_NAME);
        loggedInSessionBean.getOIDC().setCode(request.getParameter("code"));
        try {
            OAuthClientRequest accessRequest = OAuthClientRequest.
                    tokenLocation(ssoAgentConfig.getOIDC().getTokenEndpoint())
                    .setGrantType(GrantType.AUTHORIZATION_CODE)
                    .setClientId(ssoAgentConfig.getOIDC().getClientId())
                    .setClientSecret(ssoAgentConfig.getOIDC().getClientSecret())
                    .setRedirectURI(ssoAgentConfig.getOIDC().getCallBackUrl())
                    .setCode(request.getParameter("code"))
                    .buildBodyMessage();

            logger.log(Level.INFO, String.format("Sending token request to OP with following params: %s", accessRequest.getBody()));
            OAuthClient oAuthClient = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse oAuthResponse = oAuthClient.accessToken(accessRequest);
            logger.log(Level.INFO, String.format("Received response from OP for access token request including ID token:", oAuthResponse.getParam("id_token")));

            String idToken = oAuthResponse.getParam("id_token");
            loggedInSessionBean.getOIDC().setIdToken(idToken);

            if (ssoAgentConfig.getOIDC().getIsIDTokenValidationEnabled()) {
                validIDToken = validateIDTokenPayload(idToken, request) && validateIDTokenSignature(request, idToken);
            }

            if (validIDToken) {
                String accessToken = oAuthResponse.getParam("access_token");
                loggedInSessionBean.getOIDC().setAccessToken(accessToken);

                String refreshToken = oAuthResponse.getParam("refresh_token");
                loggedInSessionBean.getOIDC().setRefreshToken(refreshToken);

                loggedInSessionBean.getOIDC().setCallbackUrl(ssoAgentConfig.getOIDC().getCallBackUrl());

                JSONObject userInfoJSONObject = fetchUserInfo(ssoAgentConfig.getOIDC().getUserInfoEndpoint(), accessToken);

                if (userInfoJSONObject != null) {
                    loggedInSessionBean.getOIDC().setUserDetails(userInfoJSONObject);

                    final String userName = loggedInSessionBean.getOIDC().getUserDetails().getString("sub");
                    Principal principal = null;

                    //setting user principal

                    if (loggedInSessionBean.getOIDC() != null) {
                        principal = new Principal() {
                            @Override
                            public String getName() {
                                return userName;
                            }
                        };
                    }
                    BasicAuthenticator basicAuthenticator = new BasicAuthenticator();
                    Field field = request.getClass().getDeclaredField("request");
                    field.setAccessible(true); // getting access to (protected) field
                    Request realRequest = (Request) field.get(request);
                    basicAuthenticator.register(realRequest, response, principal, "BASIC",
                            "USER_NAME","PASSWORD");
                    //end of setting user principal

                    request.getSession(false).setAttribute("claimsMap", getClaimsMap(userInfoJSONObject));
                    request.getSession(false).setAttribute("logoutUrl",
                            "https://localhost:9443/oidc/logout?post_logout_redirect_uri="
                                    +loggedInSessionBean.getOIDC().getCallbackUrl()+"&id_token_hint="
                                    + loggedInSessionBean.getOIDC().getIdToken());
                }
            }
        } catch (OAuthProblemException e) {
            throw new SSOAgentException("Error occured while requesting an access token with client :"
                    + ssoAgentConfig.getOIDC().getClientId(), e);
        } catch (OAuthSystemException e) {
            throw new SSOAgentException("Error occured while building token request with client:"
                    + ssoAgentConfig.getOIDC().getClientId(), e);
        } catch (Exception e) {
            throw new SSOAgentException("Error occured while validating the ID token.", e);
        }
    }

    private Map<String, String> getClaimsMap(JSONObject userInfoJSONObject) {

        Map<String, String> claims = new HashMap<String, String>();

        for (Object key : userInfoJSONObject.keySet()) {
            String keyString = (String) key;
            String value = userInfoJSONObject.getString(keyString);
            claims.put(keyString, value);
        }
        return claims;
    }

    public Boolean validateIDTokenPayload(String idToken, HttpServletRequest request)
            throws ParseException, SSOAgentException {
        SignedJWT signedJWT = SignedJWT.parse(idToken);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        Boolean validIssuer = false;
        Boolean validAudience = false;
        Boolean validTimeParams = false;
        Boolean validNonce = false;

        if (ssoAgentConfig.getOIDC().getTokenEndpoint().equals(claimsSet.getIssuer())) {
            validIssuer = true;
        } else {
            throw new SSOAgentException("Issuer in JWT token does not match with the registered issuer:" +
                    ssoAgentConfig.getOIDC().getTokenEndpoint());
        }

        List<String> aud = claimsSet.getAudience();
        if (aud.contains(ssoAgentConfig.getOIDC().getClientId())) {
            validAudience = true;
        } else {
            throw new SSOAgentException("Audience of JWT token does not contains the registered id:"
                    + ssoAgentConfig.getOIDC().getClientId());
        }

        Date exp = claimsSet.getExpirationTime();
        Date iat = claimsSet.getIssueTime();
        if (exp.after(Calendar.getInstance().getTime()) && iat.before(Calendar.getInstance().getTime())) {
            validTimeParams = true;
        } else {
            throw new SSOAgentException("Validation of exp,iat failed for the JWT token:");
        }

        if (claimsSet.getStringClaim("nonce") != null) {

            if (request.getSession().getAttribute("hashOfSessionId").equals(claimsSet.getStringClaim("nonce"))) {
                validNonce = true;
            } else {
                throw new SSOAgentException("Nonce validation failed for the JWT token:");
            }

        } else {
            validNonce = true;
        }
        return validIssuer && validAudience && validTimeParams && validNonce;
    }

    public boolean validateIDTokenSignature(HttpServletRequest request, String idToken)
            throws SSOAgentException, IOException, NoSuchAlgorithmException, CertificateException,
            KeyStoreException, ParseException, JOSEException {
        RSAPublicKey publicKey = null;
        String certificateFileName = request.getServletContext().
                getInitParameter(SSOAgentConstants.CERTIFICATE_FILE_PARAMETER_NAME);
        InputStream file = request.getServletContext().getResourceAsStream("/WEB-INF/classes/"
                + certificateFileName);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(file, "wso2carbon".toCharArray());

        String alias = "wso2carbon";

        Certificate cert = keystore.getCertificate(alias);

        publicKey = (RSAPublicKey) cert.getPublicKey();

        SignedJWT signedJWT = SignedJWT.parse(idToken);

        JWSVerifier verifier = new RSASSAVerifier(publicKey);

        if (signedJWT.verify(verifier)) {
            logger.info("Validating the ID token signature was Successful");
            return true;
        } else {
            logger.warning("Validating the ID token signature step falied for the following ID token:" + idToken);
            return false;
        }

    }

    public JSONObject fetchUserInfo(String targetURL, String accessTokenIdentifier) throws SSOAgentException {
        try {
            URL myURL = new URL(targetURL);
            URLConnection myURLConnection = myURL.openConnection();
            myURLConnection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            myURLConnection.setRequestProperty("Authorization", "Bearer " + accessTokenIdentifier);
            myURLConnection.setRequestProperty("Content-Language", "en-US");
            myURLConnection.setUseCaches(false);
            myURLConnection.setDoInput(true);
            myURLConnection.setDoOutput(true);

            BufferedReader br = new BufferedReader(new InputStreamReader(myURLConnection.getInputStream()));
            String line;
            StringBuilder response = new StringBuilder();

            while ((line = br.readLine()) != null) {
                response.append(line);
                response.append('\r');
            }
            br.close();
            return new JSONObject(response.toString());
        } catch (Exception e) {
            throw new SSOAgentException("Error occured while trying to fetch user information!", e);
        }
    }

    private String generateMD5Hash(String data) throws SSOAgentException {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] messageDigest = md.digest(data.getBytes());
            BigInteger number = new BigInteger(1, messageDigest);
            String hashtext = number.toString(16);

            //adding a zero to keep the length consistent.

            while (hashtext.length() < 32) {
                hashtext = "0" + hashtext;
            }
            return hashtext;
        } catch (NoSuchAlgorithmException e) {
            throw new SSOAgentException("Error occured during the MD5 hash value generation process!", e);
        }

    }
}
