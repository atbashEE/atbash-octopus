/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.filter.AccessControlFilter;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.WebUtils;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 * Base class for all Filters that require the current user to be authenticated. This class encapsulates the
 * logic of checking whether a user is already authenticated in the system while subclasses are required to perform
 * specific logic for unauthenticated requests.
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.web.filter.authc.AuthenticationFilter"})
public abstract class AuthenticationFilter extends AccessControlFilter {

    //TODO - complete JavaDoc

    public static final String DEFAULT_SUCCESS_URL = "/";

    // FIXME Remove. Used in Shiro for the FORM authentication Filter but now replaced by User filter
    private String successUrl = DEFAULT_SUCCESS_URL;

    /**
     * Returns the success url to use as the default location a user is sent after logging in.  Typically a redirect
     * after login will redirect to the originally request URL; this property is provided mainly as a fallback in case
     * the original request URL is not available or not specified.
     * <p/>
     * The default value is {@link #DEFAULT_SUCCESS_URL}.
     *
     * @return the success url to use as the default location a user is sent after logging in.
     */
    public String getSuccessUrl() {
        return successUrl;
    }

    /**
     * Sets the default/fallback success url to use as the default location a user is sent after logging in.  Typically
     * a redirect after login will redirect to the originally request URL; this property is provided mainly as a
     * fallback in case the original request URL is not available or not specified.
     * <p/>
     * The default value is {@link #DEFAULT_SUCCESS_URL}.
     *
     * @param successUrl the success URL to redirect the user to after a successful login.
     */
    public void setSuccessUrl(String successUrl) {
        this.successUrl = successUrl;
    }

    /**
     * Determines whether the current subject is authenticated.
     * <p/>
     * The default implementation {@link #getSubject(ServletRequest, ServletResponse) acquires}
     * the currently executing Subject and then returns
     * {@link Subject#isAuthenticated() subject.isAuthenticated()};
     *
     * @return true if the subject is authenticated; false if the subject is unauthenticated
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response) {
        WebSubject subject = getSubject();
        return subject.isAuthenticated() || subject.isRemembered();
    }

    /**
     * Redirects to user to the previously attempted URL after a successful login.  This implementation simply calls
     * <code>{@link WebUtils WebUtils}.{@link WebUtils#redirectToSavedRequest(ServletRequest, ServletResponse, String) redirectToSavedRequest}</code>
     * using the {@link #getSuccessUrl() successUrl} as the {@code fallbackUrl} argument to that call.
     *
     * @param request  the incoming request
     * @param response the outgoing response
     * @throws Exception if there is a problem redirecting.
     */
    protected void issueSuccessRedirect(ServletRequest request, ServletResponse response) throws Exception {
        WebUtils.redirectToSavedRequest(request, response, getSuccessUrl());
    }

}
