/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.wso2.carbon.identity.sso.agent.bean.SSOAgentConfig;
import org.wso2.carbon.identity.sso.agent.exception.InvalidSessionException;
import org.wso2.carbon.identity.sso.agent.exception.SSOAgentException;
import org.wso2.carbon.identity.sso.agent.oidc.OIDCManager;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentConstants;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentFilterUtils;
import org.wso2.carbon.identity.sso.agent.util.SSOAgentRequestResolver;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.wso2.carbon.identity.sso.agent.bean.AppRegistrationAndConfigBean;

import static org.wso2.carbon.identity.sso.agent.util.SSOAgentFilterUtils.getSSOAgentConfig;

/**
 * Servlet Filter implementation class OIDCSSOAgentFilter.
 */
public class OIDCSSOAgentFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(SSOAgentConstants.LOGGER_NAME);
    protected FilterConfig filterConfig = null;

    /**
     * @see Filter#init(FilterConfig)
     */
    @Override
    public void init(FilterConfig fConfig) throws ServletException {
        this.filterConfig = fConfig;
    }

    /**
     * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        try {
            SSOAgentConfig ssoAgentConfig = getSSOAgentConfig(filterConfig);
            SSOAgentRequestResolver resolver
                    = new SSOAgentRequestResolver(request, response, ssoAgentConfig);

            if (resolver.isURLToSkip()) {
                chain.doFilter(servletRequest, servletResponse);
                return;
            }

            OIDCManager oidcManager;

            if (resolver.isOIDCCodeResponse(servletRequest)) {
                oidcManager = new OIDCManager(ssoAgentConfig);
                oidcManager.processCodeResponse(request, response);
                RequestDispatcher dispatcher = filterConfig.getServletContext().
                        getRequestDispatcher("/WEB-INF/home.jsp");
                dispatcher.forward(request, response);
                return;
            }

            if (resolver.isOidcSLOURL(servletRequest)) {
                response.sendRedirect(filterConfig.getServletContext().getContextPath());
                return;
            }

            if (resolver.isOIDCURL()) {
                AppRegistrationAndConfigBean regAndConfBean = new AppRegistrationAndConfigBean();
                RequestDispatcher requestDispatcher = null;

                //check if the application is registered in the IDP
                if (!regAndConfBean.checkAppRegistrationStatus(ssoAgentConfig.getOIDC().getSpName())) {
                    LOGGER.log(Level.INFO, String.format("Application %s has not been Registered Yet!",
                            ssoAgentConfig.getOIDC().getSpName()));
                    if (ssoAgentConfig.isDynamicAppRegistrationEnabled()) {
                        // do dynamic registration
                        regAndConfBean.performDynamicAppRegistration(ssoAgentConfig.getOIDC().getSpName());
                    } else {
                        request.setAttribute("message", "Your Application is not yet registed with IDP. "
                                + "Either register in IDP or enable dynamic Registraion from properties file!");
                        requestDispatcher = request.getRequestDispatcher("index.jsp");
                        requestDispatcher.forward(request, response);
                    }
                }

                //check whether the app is configured to use OIDC
                if (!regAndConfBean.checkOIDCconfigurationStatus(ssoAgentConfig.getOIDC().getSpName())) {
                    if (ssoAgentConfig.isDynamicOIDCConfigEnabled()) {
                        // perform dynamic oidc configuration
                        String status = regAndConfBean.performDynamicOIDCConfiguration(ssoAgentConfig);

                        if (!"updated".equals(status)) {
                            request.setAttribute("message", status);
                            requestDispatcher = request.getRequestDispatcher("index.jsp");
                            requestDispatcher.forward(request, response);
                        }
                    } else {
                        request.setAttribute("message", "Your Application has not yet configured to use OIDC. "+
                                "Either configure using management console or enable dynamic saml configuration from" +
                                " properties file!");
                        requestDispatcher = request.getRequestDispatcher("index.jsp");
                        requestDispatcher.forward(request, response);
                    }
                }
                oidcManager = new OIDCManager(ssoAgentConfig);
                response.sendRedirect(oidcManager.doOIDCLogin(request, response));
                return;
            }

            if (SSOAgentFilterUtils.shouldGoToWelcomePage(request)) {
                response.sendRedirect(filterConfig.getServletContext().getContextPath());
                return;
            }

            // pass the request along the filter chain
            chain.doFilter(request, response);
        } catch (InvalidSessionException e) {
            // Redirect to the index page when session is expired or user already logged out.
            request.setAttribute(SSOAgentConstants.SHOULD_GO_TO_WELCOME_PAGE, "true");

            // pass the request along the filter chain
            chain.doFilter(request, response);
        } catch (SSOAgentException e) {
            LOGGER.log(Level.SEVERE, "An error has occurred", e);
            throw e;
        }
    }

    /**
     * @see Filter#destroy()
     */
    @Override
    public void destroy() {
        return;
    }

    protected void handleException(HttpServletRequest request, SSOAgentException e)
            throws SSOAgentException {

        if (request.getSession(false) != null) {
            request.getSession(false).removeAttribute(SSOAgentConstants.SESSION_BEAN_NAME);
        }
        throw e;
    }

}
