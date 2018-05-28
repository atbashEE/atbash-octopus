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
import be.atbash.ee.security.octopus.filter.AccessControlFilter;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.util.Reviewed;

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
 * Concrete implementations will be used to have support for Form, Keycloak, Google (OAuth2, ...)
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.filter.authc.UserFilter"})
@Reviewed
public class AbstractUserFilter extends AccessControlFilter {

    private static final String FACES_REDIRECT_XML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<partial-response><redirect url=\"%s\"></redirect></partial-response>";

    @Inject
    private OctopusJSFConfiguration jsfConfiguration;

    /**
     * Returns <code>true</code> if the request is a
     * {@link #isLoginRequest(ServletRequest) loginRequest} or
     * if the current {@link WebSubject subject}
     * is authenticated or remembered, <code>false</code> otherwise.
     *
     * @return <code>true</code> if the request is a
     * {@link #isLoginRequest(ServletRequest) loginRequest} or
     * if the current {@link WebSubject subject}
     * is authenticated or remembered,, <code>false</code> otherwise.
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response, Object mappedValue) {
        if (isLoginRequest(request)) {
            return true;
        } else {
            WebSubject subject = getSubject();
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
        boolean postIsAllowedSavedRequest = jsfConfiguration.getPostIsAllowedSavedRequest();

        HttpServletRequest req = (HttpServletRequest) request;
        if (POST_METHOD.equals(req.getMethod()) && !postIsAllowedSavedRequest) {
            redirectToLogin(request, response);
        } else {
            saveRequestAndRedirectToLogin(request, response);
        }
        return false;
    }

    /**
     * Redirect to the login page, but has support for AJAX requests.
     *
     * @param request
     * @param response
     * @throws IOException
     */
    @Override
    protected void redirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        HttpServletRequest servletRequest = (HttpServletRequest) request;

        if ("partial/ajax".equals(servletRequest.getHeader("Faces-Request"))) {
            response.setContentType("text/xml");
            response.setCharacterEncoding("UTF-8");

            String loginUrl = getLoginUrl();
            if (loginUrl.startsWith("/") || !loginUrl.startsWith("http")) {
                // If it is a relative URL, use the context path.
                loginUrl = servletRequest.getContextPath() + loginUrl;
            }
            response.getWriter().printf(FACES_REDIRECT_XML, loginUrl);
        } else {
            super.redirectToLogin(servletRequest, response);
        }
    }

    @Override
    protected boolean isLoginRequest(ServletRequest request) {
        prepareLoginURL(request);
        return super.isLoginRequest(request);
    }

    /**
     * Override in subclasses to have specific logic for the preparation of the URL (like CAS, Google OAuth2, ...)
     * Also called from the ??DuringAuthenticationFilter?? to make sure we have the correct loginURL.
     *
     * @param request
     */
    protected void prepareLoginURL(ServletRequest request) {
        // Override in subclasses if needed.
    }

}
