/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package be.atbash.ee.security.octopus.filter.authc;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.context.OctopusSecurityContext;
import be.atbash.ee.security.octopus.filter.AdviceFilter;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.ee.security.octopus.view.OctopusJSFSecurityContext;
import be.atbash.util.CDIUtils;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.util.Locale;

/**
 * Simple Filter that, upon receiving a request, will immediately log-out the currently executing
 * subject.
 */
@ApplicationScoped
@ShiroEquivalent(shiroClassNames = "org.apache.shiro.web.filter.authc.LogoutFilter")
public class LogoutFilter extends AdviceFilter {

    /**
     * Due to browser pre-fetching, using a GET requests for logout my cause a user to be logged accidentally, for example:
     * out while typing in an address bar.  If <code>postOnlyLogout</code> is <code>true</code>. Only POST requests will cause
     * a logout to occur.
     */
    private boolean postOnlyLogout = false;

    private OctopusSecurityContext securityContext;

    @PostConstruct
    public void initInstance() {
        setName("logout");

        securityContext = CDIUtils.retrieveInstance(OctopusJSFSecurityContext.class);

        OctopusJSFConfiguration configuration = CDIUtils.retrieveInstance(OctopusJSFConfiguration.class);
        postOnlyLogout = configuration.getLogoutFilterPostOnly();
    }

    /**
     * Acquires the currently executing {@link #getSubject(ServletRequest, ServletResponse) subject},
     * a potentially Subject or request-specific
     * {@link #getRedirectUrl(ServletRequest, ServletResponse, org.apache.shiro.subject.Subject) redirectUrl},
     * and redirects the end-user to that redirect url.
     *
     * @param request  the incoming ServletRequest
     * @param response the outgoing ServletResponse
     * @return {@code false} always as typically no further interaction should be done after user logout.
     * @throws Exception if there is any error.
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {

        // Check if POST only logout is enabled
        if (postOnlyLogout) {

            // check if the current request's method is a POST, if not redirect
            if (!WebUtils.toHttp(request).getMethod().toUpperCase(Locale.ENGLISH).equals("POST")) {
                return onLogoutRequestNotAPost(request, response);
            }
        }

        securityContext.logout();
        return false;
    }

    /**
     * This method is called when <code>postOnlyLogout</code> is <code>true</code>, and the request was NOT a <code>POST</code>.
     * For example if this filter is bound to '/logout' and the caller makes a GET request, this method would be invoked.
     * <p>
     * The default implementation sets the response code to a 405, and sets the 'Allow' header to 'POST', and
     * always returns false.
     * </p>
     *
     * @return The return value indicates if the processing should continue in this filter chain.
     */
    protected boolean onLogoutRequestNotAPost(ServletRequest request, ServletResponse response) {

        HttpServletResponse httpServletResponse = WebUtils.toHttp(response);
        httpServletResponse.setStatus(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        httpServletResponse.setHeader("Allow", "POST");
        return false;
    }

}
