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

import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.IncorrectDataToken;
import be.atbash.ee.security.octopus.jwt.decoder.JWTData;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.jwt.keys.JWKManagerKeySelector;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.MPJWTToken;
import be.atbash.ee.security.octopus.token.MPToken;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static be.atbash.ee.security.octopus.WebConstants.AUTHORIZATION_HEADER;
import static be.atbash.ee.security.octopus.WebConstants.BEARER;

/**
 *
 */
@ApplicationScoped
public class MPUserFilter extends AuthenticatingFilter {

    @Inject
    private JWTDecoder jwtDecoder;

    @Inject
    private JWKManagerKeySelector keySelector;

    @Inject
    private MPBearerTokenVerifier verifier;

    @PostConstruct
    public void initInstance() {
        setName("mpUser");
    }

    @Override
    protected AuthenticationToken createToken(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        String token = httpServletRequest.getHeader(AUTHORIZATION_HEADER);

        if (token == null) {
            // Authorization header parameter is required.
            return new IncorrectDataToken("Authorization header required");
        }

        String[] parts = token.split(" ");
        if (parts.length != 2) {
            return new IncorrectDataToken("Authorization header value incorrect");
        }
        if (!BEARER.equals(parts[0])) {
            return new IncorrectDataToken("Authorization header value must start with Bearer");
        }

        return createToken(parts[1]);
    }

    private AuthenticationToken createToken(String token) {

        JWTData<MPJWTToken> data = jwtDecoder.decode(token, MPJWTToken.class, keySelector, verifier);
        return new MPToken(data.getData());

    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return executeLogin(request, response);
    }

    @Override
    protected boolean onLoginFailure(AuthenticationToken token, AuthenticationException e, ServletRequest request, ServletResponse response) {
        ((HttpServletResponse) response).setStatus(401);
        return false; // Stop the filter chain
    }
}
