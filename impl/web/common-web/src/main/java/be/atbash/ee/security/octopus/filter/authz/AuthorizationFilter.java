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
package be.atbash.ee.security.octopus.filter.authz;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.filter.AccessControlFilter;
import be.atbash.ee.security.octopus.subject.WebSubject;

import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Superclass for authorization-related filters.  If an request is unauthorized, response handling is delegated to the
 * {@link #onAccessDenied(ServletRequest, ServletResponse) onAccessDenied} method, which
 * provides reasonable handling for most applications.
 *
 * @see #onAccessDenied(ServletRequest, ServletResponse)
 */
@ShiroEquivalent(shiroClassNames = "org.apache.shiro.web.filter.authz.AuthorizationFilter")
public abstract class AuthorizationFilter extends AccessControlFilter {

    @Inject
    private AccessDeniedHandler accessDeniedHandler;

    /**
     * Handles the response when access has been denied.  It behaves as follows:
     * <ul>
     * <li>If the {@code Subject} is unknown<sup><a href="#known">[1]</a></sup>:
     * <ol><li>The incoming request will be saved and they will be redirected to the login page for authentication
     * (via the {@link #saveRequestAndRedirectToLogin(ServletRequest, ServletResponse)}
     * method).</li>
     * <li>Once successfully authenticated, they will be redirected back to the originally attempted page.</li></ol>
     * </li>
     * <li>If the Subject is known:</li>
     * <ol>
     * <li>The HTTP {@link HttpServletResponse#SC_UNAUTHORIZED} header will be set (401 Unauthorized)</li>
     * <li>If the {@link #getUnauthorizedUrl() unauthorizedUrl} has been configured, a redirect will be issued to that
     * URL.  Otherwise the 401 response is rendered normally</li>
     * </ul>
     * <code><a name="known">[1]</a></code>: A {@code Subject} is 'known' when
     * <code>subject.{@link WebSubject#getPrincipal() getPrincipal()}</code> is not {@code null},
     * which implicitly means that the subject is either currently authenticated or they have been remembered via
     * 'remember me' services.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return {@code false} always for this implementation.
     * @throws IOException if there is any servlet error.
     */
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {

        return accessDeniedHandler.onAccessDenied(request, response);
    }

}
