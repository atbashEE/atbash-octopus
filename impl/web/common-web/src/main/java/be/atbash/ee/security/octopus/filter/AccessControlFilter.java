/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.filter;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.WebUtils;
import be.atbash.util.Reviewed;

import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import java.io.IOException;

/**
 * Superclass for any filter that controls access to a resource and may redirect the user to the login page
 * if they are not authenticated.  This superclass provides the method
 * {@link #saveRequestAndRedirectToLogin(ServletRequest, ServletResponse)}
 * which is used by many subclasses as the behavior when a user is unauthenticated.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.filter.AccessControlFilter"})
@Reviewed
public abstract class AccessControlFilter extends PathMatchingFilter {

    /**
     * Constant representing the HTTP 'GET' request method, equal to <code>GET</code>.
     */
    public static final String GET_METHOD = "GET";

    /**
     * Constant representing the HTTP 'POST' request method, equal to <code>POST</code>.
     */
    public static final String POST_METHOD = "POST";

    /**
     * The login url to used to authenticate a user, used when redirecting users if authentication is required.
     */
    // TODO Verify we can have an AuthenticatingFilter (perform authentication based on the request info like header)
    // without the methods in this class? Directly descent from PathMatchingFilter?
    private String loginUrl;

    /**
     * Returns the login URL used to authenticate a user.
     * <p/>
     *
     * @return the login URL used to authenticate a user, used when redirecting users if authentication is required.
     */
    public String getLoginUrl() {
        // TODO Verify, we have no longer a default LoginURL; Do we need to check it here or somewhere else (that we do have one in the case it is used)
        return loginUrl;
    }

    /**
     * Sets the login URL used to authenticate a user.
     * <p/>
     *
     * @param loginUrl the login URL used to authenticate a user, used when redirecting users if authentication is required.
     */
    protected void setLoginUrl(String loginUrl) {
        this.loginUrl = loginUrl;
    }

    /**
     * Convenience method that acquires the Subject associated with the request.
     * <p/>
     * The implementation simply returns
     * {@link SecurityUtils#getSubject() SecurityUtils.getSubject()}.
     *
     * @return the Subject associated with the request.
     */
    protected WebSubject getSubject() {
        return SecurityUtils.getSubject();
    }

    /**
     * Returns <code>true</code> if the request is allowed to proceed through the filter normally, or <code>false</code>
     * if the request should be handled by the
     * {@link #onAccessDenied(ServletRequest, ServletResponse) onAccessDenied(request,response)}
     * method instead.
     *
     * @param request     the incoming <code>ServletRequest</code>
     * @param response    the outgoing <code>ServletResponse</code>
     * @return <code>true</code> if the request should proceed through the filter normally, <code>false</code> if the
     * request should be processed by this filter's
     * {@link #onAccessDenied(ServletRequest, ServletResponse)} method instead.
     * @throws Exception if an error occurs during processing.
     */
    protected abstract boolean isAccessAllowed(ServletRequest request, ServletResponse response) throws Exception;

    /**
     * Processes requests where the subject was denied access as determined by the
     * {@link #isAccessAllowed(ServletRequest, ServletResponse) isAccessAllowed}
     * method.
     * <p/>
     *
     * @param request    the incoming <code>ServletRequest</code>
     * @param response   the outgoing <code>ServletResponse</code>
     * @return <code>true</code> if the request should continue to be processed; false if the subclass will
     * handle/render the response directly.
     * @throws Exception if there is an error processing the request.
     */
    protected abstract boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception;

    /**
     * Returns <code>true</code> if
     * {@link #isAccessAllowed(ServletRequest, ServletResponse) isAccessAllowed(Request,Response,Object)},
     * otherwise returns the result of
     * {@link #onAccessDenied(ServletRequest, ServletResponse) onAccessDenied(Request,Response,Object)}.
     *
     * @return <code>true</code> if
     * {@link #isAccessAllowed(ServletRequest, ServletResponse) isAccessAllowed},
     * otherwise returns the result of
     * {@link #onAccessDenied(ServletRequest, ServletResponse) onAccessDenied}.
     * @throws Exception if an error occurs.
     */
    public boolean onPreHandle(ServletRequest request, ServletResponse response) throws Exception {
        return isAccessAllowed(request, response) || onAccessDenied(request, response);
    }

    /**
     * Returns <code>true</code> if the incoming request is a login request, <code>false</code> otherwise.
     * <p/>
     * The default implementation merely returns <code>true</code> if the incoming request matches the configured
     * {@link #getLoginUrl() loginUrl} by calling
     * <code>{@link #pathsMatch(String, String) pathsMatch(loginUrl, request)}</code>.
     *
     * @param request the incoming <code>ServletRequest</code>
     * @return <code>true</code> if the incoming request is a login request, <code>false</code> otherwise.
     */
    protected boolean isLoginRequest(ServletRequest request) {
        return pathsMatch(getLoginUrl(), request);
    }

    /**
     * Convenience method for subclasses to use when a login redirect is required.
     * <p/>
     * This implementation simply calls {@link WebUtils#saveRequest(ServletRequest) saveRequest(request)}
     * and then {@link #redirectToLogin(ServletRequest, ServletResponse) redirectToLogin(request,response)}.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @throws IOException if an error occurs.
     */
    public void saveRequestAndRedirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        WebUtils.saveRequest(request);
        redirectToLogin(request, response);
    }

    /**
     * Convenience method for subclasses that merely acquires the {@link #getLoginUrl() getLoginUrl} and redirects
     * the request to that url.
     * <p/>
     * <b>N.B.</b>  If you want to issue a redirect with the intention of allowing the user to then return to their
     * originally requested URL, don't use this method directly.  Instead you should call
     * {@link #saveRequestAndRedirectToLogin(ServletRequest, ServletResponse)
     * saveRequestAndRedirectToLogin(request,response)}, which will save the current request state so that it can
     * be reconstructed and re-used after a successful login.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @throws IOException if an error occurs.
     */
    protected void redirectToLogin(ServletRequest request, ServletResponse response) throws IOException {
        String loginUrl = getLoginUrl();
        WebUtils.issueRedirect(request, response, loginUrl);
    }

}
