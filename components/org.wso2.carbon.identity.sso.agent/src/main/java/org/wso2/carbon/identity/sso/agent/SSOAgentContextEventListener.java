/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sso.agent;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.sso.agent.bean.SSOAgentConfig;
import org.wso2.carbon.identity.sso.agent.exception.SSOAgentException;
import org.wso2.carbon.identity.sso.agent.security.SSOAgentX509Credential;
import org.wso2.carbon.identity.sso.agent.security.SSOAgentX509KeyStoreCredential;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentConstants;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

/**
 * Context EventListner Class for SAML2 SSO and OIDC.
 */
public class SSOAgentContextEventListener implements ServletContextListener {

    private static Logger logger = Logger.getLogger(SSOAgentContextEventListener.class.getName());

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        Properties properties = new Properties();
        Boolean hasPropertyFile = false;
        try {
            ServletContext servletContext = servletContextEvent.getServletContext();

            // Load the client property-file, if not specified throw SSOAgentException
            String propertyFileName = servletContext.getInitParameter(SSOAgentConstants.PROPERTY_FILE_PARAMETER_NAME);
            if (StringUtils.isNotBlank(propertyFileName)) {
                hasPropertyFile = true;
                properties.load(servletContextEvent.getServletContext().
                        getResourceAsStream("/WEB-INF/classes/" + propertyFileName));
            } else
                hasPropertyFile = false;

            // Load the client security certificate, if not specified throw SSOAgentException.
            String certificateFileName = servletContext.getInitParameter(SSOAgentConstants
                    .CERTIFICATE_FILE_PARAMETER_NAME);
            InputStream keyStoreInputStream;
            if (StringUtils.isNotBlank(certificateFileName)) {
                keyStoreInputStream = servletContext.getResourceAsStream("/WEB-INF/classes/"
                        + certificateFileName);
            } else {
                throw new SSOAgentException(SSOAgentConstants.CERTIFICATE_FILE_PARAMETER_NAME
                        + " context-param is not specified in the web.xml");
            }

            SSOAgentX509Credential credential;
            if (hasPropertyFile) {
                credential = new SSOAgentX509KeyStoreCredential(keyStoreInputStream,
                        properties.getProperty("KeyStorePassword").toCharArray(),
                        properties.getProperty("IdPPublicCertAlias"),
                        properties.getProperty("PrivateKeyAlias"),
                        properties.getProperty("PrivateKeyPassword").toCharArray());
            } else {
                credential = new SSOAgentX509KeyStoreCredential(keyStoreInputStream,
                        "wso2carbon".toCharArray(),
                        "wso2carbon", "wso2carbon",
                        "wso2carbon".toCharArray());
            }

            SSOAgentConfig config = new SSOAgentConfig();

            if (!hasPropertyFile) {
                //set default properties when the sso.properties file is not available
                properties.setProperty("KeyStorePassword", "wso2carbon");
                properties.setProperty("IdPPublicCertAlias", "wso2carbon");
                properties.setProperty("PrivateKeyAlias", "wso2carbon");
                properties.setProperty("PrivateKeyPassword", "wso2carbon");

                String isSAMLEnabledString = servletContext.getInitParameter(SSOAgentConstants.SSOAgentConfig.ENABLE_SAML2_SSO_LOGIN);
                Boolean isSAMLEnabled = false;
                if (StringUtils.isNotBlank(isSAMLEnabledString)) {
                    isSAMLEnabled = Boolean.parseBoolean(isSAMLEnabledString);
                }

                if (isSAMLEnabled) {
                    properties.setProperty("EnableSAML2SSOLogin", "true");
                    properties.setProperty("SAML2SSOURL", "samlsso");
                    properties.setProperty("SAML2.IdPEntityId", "localhost");
                    properties.setProperty("SAML2.IdPURL", "https://localhost:9443/samlsso");
                    properties.setProperty("SAML2.EnableRequestSigning", "true");

                    properties.setProperty("SAML2.EnableSLO", "true");
                    properties.setProperty("SAML2.SLOURL", "samllogout");

                    String acsURL = servletContext.getInitParameter(SSOAgentConstants.SSOAgentConfig.SAML2.ACS_URL);
                    if (StringUtils.isNotBlank(acsURL)) {
                        properties.setProperty("SAML2.AssertionConsumerURL", acsURL);
                    } else {
                        throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.SAML2.ACS_URL
                                + " context-param is not specified in the web.xml");
                    }

                    String spEntityId = servletContext.getInitParameter(SSOAgentConstants.SSOAgentConfig.SAML2.
                            SP_ENTITY_ID);
                    if (StringUtils.isNotBlank(spEntityId)) {
                        properties.setProperty("SAML2.SPEntityId", spEntityId);
                    } else {
                        throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.SAML2.SP_ENTITY_ID
                                + " context-param is not specified in the web.xml");
                    }

                    String enableSAMLSLOString = servletContext.getInitParameter(SSOAgentConstants.SSOAgentConfig.SAML2.
                            ENABLE_SLO);
                    if (StringUtils.isNotBlank(enableSAMLSLOString)) {
                        properties.setProperty("SAML2.EnableSLO", enableSAMLSLOString);
                    }

                }


                Boolean isOIDCEnabled = false;
                String isOIDCEnabledString = servletContext.getInitParameter(
                        SSOAgentConstants.SSOAgentConfig.ENABLE_OIDC_SSO_LOGIN);
                if (StringUtils.isNotBlank(isOIDCEnabledString)) {
                    isOIDCEnabled = Boolean.parseBoolean(isOIDCEnabledString);
                }

                if (isOIDCEnabled) {

                    properties.setProperty("EnableOIDCSSOLogin", "true");
                    properties.setProperty("OIDCSSOURL", "oidcsso");
                    String spName = servletContext.getInitParameter(SSOAgentConstants.SSOAgentConfig.OIDC.
                            SERVICE_PROVIDER_NAME);
                    if (StringUtils.isNotBlank(spName)) {
                        properties.setProperty("OIDC.spName", spName);
                    } else {
                        throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.SERVICE_PROVIDER_NAME
                                + " context-param is not specified in the web.xml");
                    }

                    String clientId = servletContext.getInitParameter(SSOAgentConstants.SSOAgentConfig.OIDC.CLIENT_ID);
                    if (StringUtils.isNotBlank(clientId)) {
                        properties.setProperty("OIDC.ClientId", clientId);
                    } else {
                        throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.CLIENT_ID
                                + " context-param is not specified in the web.xml");
                    }

                    String clientSecret = servletContext.getInitParameter(SSOAgentConstants.SSOAgentConfig.OIDC.
                            CLIENT_SECRET);
                    if (StringUtils.isNotBlank(clientSecret)) {
                        properties.setProperty("OIDC.ClientSecret", clientSecret);
                    } else {
                        throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.CLIENT_SECRET
                                + " context-param is not specified in the web.xml");
                    }

                    String callBackUrl = servletContext.getInitParameter(SSOAgentConstants.SSOAgentConfig.OIDC.
                            CALL_BACK_URL);
                    if (StringUtils.isNotBlank(callBackUrl)) {
                        properties.setProperty("OIDC.CallBackUrl", callBackUrl);
                    } else {
                        throw new SSOAgentException(SSOAgentConstants.SSOAgentConfig.OIDC.CALL_BACK_URL
                                + " context-param is not specified in the web.xml");
                    }

                    String enableIDTokenValidationString = servletContext.getInitParameter(
                            SSOAgentConstants.SSOAgentConfig.OIDC.ENABLE_ID_TOKEN_VALIDATION);
                    if (StringUtils.isNotBlank(enableIDTokenValidationString)) {
                        properties.setProperty("OIDC.EnableIDTokenValidation", enableIDTokenValidationString);
                    }

                    properties.setProperty("OIDC.AuthorizeEndpoint", "https://localhost:9443/oauth2/authorize");
                    properties.setProperty("OIDC.TokenEndpoint", "https://localhost:9443/oauth2/token");
                    properties.setProperty("OIDC.UserInfoEndpoint",
                            "https://localhost:9443/oauth2/userinfo?schema=openid");
                    properties.setProperty("OIDC.GrantType", "code");
                    properties.setProperty("OIDC.Scope", "openid");

                }
            }
            config.initConfig(properties);
            config.getSAML2().setSSOAgentX509Credential(credential);
            servletContext.setAttribute(SSOAgentConstants.CONFIG_BEAN_NAME, config);

        } catch (IOException e) {
            logger.log(Level.SEVERE, e.getMessage(), e);
            System.out.println("IOEXception: " + e.getMessage());
        } catch (SSOAgentException e) {
            logger.log(Level.SEVERE, e.getMessage(), e);
            System.out.println("SSOAgentException: " + e.getMessage());
        }
    }

    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
    }

}
