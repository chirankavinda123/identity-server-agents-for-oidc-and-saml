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
 *
 *
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
import java.lang.reflect.Field;
import java.security.Principal;
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
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.connector.Request;
import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.sso.agent.bean.LoggedInSessionBean;

public class HomePageRequestFilter implements Filter {

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
            SSOAgentConfig ssoAgentConfig = SSOAgentFilterUtils.getSSOAgentConfig(filterConfig);

            SSOAgentRequestResolver resolver
                    = new SSOAgentRequestResolver(request, response, ssoAgentConfig);

            if (request.getSession().getAttribute(SSOAgentConstants.SESSION_BEAN_NAME) == null) {
                response.sendRedirect(filterConfig.getServletContext().getContextPath());
                return;
            } else {
                RequestDispatcher dispatcher = filterConfig.getServletContext().getRequestDispatcher("/WEB-INF/home.jsp");
                final LoggedInSessionBean loggedInSessionBean = (LoggedInSessionBean) request.getSession().
                        getAttribute(SSOAgentConstants.SESSION_BEAN_NAME);

                dispatcher.forward(request, response);
            }

        } catch (InvalidSessionException e) {
            request.setAttribute(SSOAgentConstants.SHOULD_GO_TO_WELCOME_PAGE, "true");

        } catch (SSOAgentException e) {
            LOGGER.log(Level.SEVERE, "An error has occurred", e);
            throw e;
        }  catch (SecurityException ex) {
            Logger.getLogger(HomePageRequestFilter.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalArgumentException ex) {
            Logger.getLogger(HomePageRequestFilter.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * @see Filter#destroy()
     */
    @Override
    public void destroy() {
        return;
    }

}
