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
package be.atbash.ee.security.octopus.filter;

import be.atbash.ee.security.octopus.filter.authc.AuthenticatingFilter;
import be.atbash.ee.security.octopus.filter.mgt.ErrorInfo;
import be.atbash.ee.security.octopus.util.ExceptionUtil;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
public abstract class RestAuthenticatingFilter extends AuthenticatingFilter {

    /**
     * Overrides the default behavior to show and swallow the exception if the exception is
     * UnauthenticatedException or UnauthorizedException. {@link ExceptionUtil}
     */
    @Override
    protected void cleanup(ServletRequest request, ServletResponse response, Throwable existing) throws ServletException, IOException {

        Throwable unwrappedException = ExceptionUtil.unwrap(existing);
        if (ExceptionUtil.isUnauthorizedException(unwrappedException) || ExceptionUtil.isUnauthenticatedException(unwrappedException)) {
            try {

                HttpServletResponse servletResponse = (HttpServletResponse) response;
                servletResponse.reset();

                servletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                servletResponse.setHeader("Content-Type", "application/json");

                ErrorInfo info = new ErrorInfo("OCT-002", unwrappedException.getMessage());
                servletResponse.getWriter().print(info.toJSON());
                unwrappedException = null;
            } catch (Exception e) {
                unwrappedException = e;
            }
        }
        super.cleanup(request, response, unwrappedException);

    }

}
