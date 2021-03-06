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
package be.atbash.ee.security.octopus.filter.authz;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.filter.AccessControlFilter;

import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

/**
 * Superclass for authorization-related filters.  If an request is unauthorized, response handling is delegated to the
 * {@link #onAccessDenied(ServletRequest, ServletResponse, String[]) onAccessDenied} method, which
 * provides reasonable handling for most applications.
 *
 * @see #onAccessDenied(ServletRequest, ServletResponse, String[])
 */
@ShiroEquivalent(shiroClassNames = "org.apache.shiro.web.filter.authz.AuthorizationFilter")
public abstract class AuthorizationFilter extends AccessControlFilter {

    @Inject
    private AccessDeniedHandler accessDeniedHandler;

    /**
     * Handles the response when access has been denied.
     *
     * @param request  the incoming <code>ServletRequest</code>
     * @param response the outgoing <code>ServletResponse</code>
     * @return {@code false} always so that filter chain stops.
     * @throws IOException if there is any servlet error.
     */
    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws IOException {
        // FIXME Review AuthorizationFilter subclasses if this doesn't need to be overwritten.
        return accessDeniedHandler.onAccessDenied(request, response);
    }

}
