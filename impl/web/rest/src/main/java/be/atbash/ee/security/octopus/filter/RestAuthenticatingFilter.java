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
package be.atbash.ee.security.octopus.filter;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.IncorrectDataToken;
import be.atbash.ee.security.octopus.authc.InvalidCredentialsException;
import be.atbash.ee.security.octopus.fake.LoginAuthenticationTokenProvider;
import be.atbash.ee.security.octopus.filter.authc.AuthenticatingFilter;
import be.atbash.ee.security.octopus.filter.mgt.ErrorInfo;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.ExceptionUtil;
import be.atbash.util.CDIUtils;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.annotation.PostConstruct;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
public abstract class RestAuthenticatingFilter extends AuthenticatingFilter {

    private LoginAuthenticationTokenProvider loginAuthenticationTokenProvider;

    @PostConstruct
    public void init() {
        loginAuthenticationTokenProvider = CDIUtils.retrieveOptionalInstance(LoginAuthenticationTokenProvider.class);
    }

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

        if (unwrappedException instanceof InvalidCredentialsException) {
            HttpServletResponse servletResponse = (HttpServletResponse) response;
            servletResponse.reset();

            // This is still a 401, unauthorized because of missing header info
            servletResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            servletResponse.setHeader("Content-Type", "application/json");

            ErrorInfo info = new ErrorInfo("OCT-002", unwrappedException.getMessage());
            servletResponse.getWriter().print(info.toJSON());
            unwrappedException = null;

        }
        super.cleanup(request, response, unwrappedException);

    }

    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException authenticationexception, ServletRequest request, ServletResponse response) {
        try {
            cleanup(request, response, authenticationexception);
        } catch (ServletException | IOException e) {
            throw new AtbashUnexpectedException(e);
        }
        return false; // Stop the filter chain
    }

    protected String getAuthzHeader(ServletRequest request) {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        return httpServletRequest.getHeader(OctopusConstants.AUTHORIZATION_HEADER);
    }

    @Override
    protected final AuthenticationToken createToken(ServletRequest request, ServletResponse response) {
        String token = getAuthzHeader(request);

        if (token == null) {
            // Authorization header parameter is required.
            return new IncorrectDataToken("Authorization header required");
        }

        String[] parts = token.split(" ");
        if (parts.length != 2) {
            return new IncorrectDataToken("Authorization header value incorrect");
        }
        if (!OctopusConstants.BEARER.equals(parts[0])) {
            return new IncorrectDataToken("Authorization header value must start with Bearer");
        }

        return createToken((HttpServletRequest) request, parts[1]);
    }

    protected abstract AuthenticationToken createToken(HttpServletRequest httpServletRequest, String token);

    protected LoginAuthenticationTokenProvider getLoginAuthenticationTokenProvider() {
        return loginAuthenticationTokenProvider;
    }
}
