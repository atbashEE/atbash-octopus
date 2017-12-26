/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.filter.AccessControlFilter;
import be.atbash.ee.security.octopus.subject.WebSubject;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

/**
 * Filter that allows access to resources if the accessor is a known user, which is defined as
 * having a known principal.  This means that any user who is authenticated or remembered via a
 * 'remember me' feature will be allowed access from this filter.
 * <p/>
 * If the accessor is not a known user, then they will be redirected to the {@link #setLoginUrl(String) loginUrl}</p>
 */
@ApplicationScoped
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.filter.authc.UserFilter"})
public class UserFilter extends AccessControlFilter {

    @Inject
    private OctopusJSFConfiguration octopusJSFConfiguration;

    @PostConstruct
    public void initInstance() {
        setName("user");

        setLoginUrl(octopusJSFConfiguration.getLoginPage());

    }

    /**
     * Returns <code>true</code> if the request is a
     * {@link #isLoginRequest(ServletRequest, ServletResponse) loginRequest} or
     * if the current {@link #getSubject(ServletRequest, ServletResponse) subject}
     * is not <code>null</code>, <code>false</code> otherwise.
     *
     * @return <code>true</code> if the request is a
     * {@link #isLoginRequest(ServletRequest, ServletResponse) loginRequest} or
     * if the current {@link #getSubject(ServletRequest, ServletResponse) subject}
     * is not <code>null</code>, <code>false</code> otherwise.
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (isLoginRequest(request, response)) {
            return true;
        } else {
            WebSubject subject = getSubject(request, response);
            // If principal is not null, then the user is known and should be allowed access.
            return subject.getPrincipal() != null && (subject.isAuthenticated() || subject.isRemembered());
        }
    }

    /**
     * This default implementation simply calls
     * {@link #saveRequestAndRedirectToLogin(ServletRequest, ServletResponse) saveRequestAndRedirectToLogin}
     * and then immediately returns <code>false</code>, thereby preventing the chain from continuing so the redirect may
     * execute.
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        boolean postIsAllowedSavedRequest = octopusJSFConfiguration.getPostIsAllowedSavedRequest();

        HttpServletRequest req = (HttpServletRequest) request;
        if ("POST".equals(req.getMethod()) && !postIsAllowedSavedRequest) {
            redirectToLogin(request, response);
        } else {
            saveRequestAndRedirectToLogin(request, response);
        }
        return false;
    }

    private static final String FACES_REDIRECT_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<partial-response><redirect url=\"%s\"></redirect></partial-response>";

    @Override
    protected void redirectToLogin(ServletRequest req, ServletResponse res) throws IOException {
        HttpServletRequest request = (HttpServletRequest) req;

        if ("partial/ajax".equals(request.getHeader("Faces-Request"))) {
            res.setContentType("text/xml");
            res.setCharacterEncoding("UTF-8");

            String loginUrl = getLoginUrl();
            if (loginUrl.startsWith("/") || !loginUrl.startsWith("http")) {
                // If it is a relative URL, use the context path.
                loginUrl = request.getContextPath() + loginUrl;
            }
            res.getWriter().printf(FACES_REDIRECT_XML, loginUrl);
        } else {
            super.redirectToLogin(req, res);
        }
    }

    @Override
    protected boolean isLoginRequest(ServletRequest request, ServletResponse response) {
        prepareLoginURL(request, response);
        return super.isLoginRequest(request, response);
    }

    /**
     * Override in subclasses to have specific logic for the preparation of the URL (like CAS, Google OAuth2, ...)
     * Also called from the ??DuringAuthenticationFilter?? to make sure we have the correct loginURL.
     *
     * @param request
     * @param response
     */
    public void prepareLoginURL(ServletRequest request, ServletResponse response) {
        // Override in subclasses if needed.
    }

}
