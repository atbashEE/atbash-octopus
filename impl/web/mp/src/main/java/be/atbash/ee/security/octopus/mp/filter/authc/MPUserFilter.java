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
package be.atbash.ee.security.octopus.mp.filter.authc;

import be.atbash.ee.security.octopus.filter.RestAuthenticatingFilter;
import be.atbash.ee.security.octopus.jwt.decoder.JWTData;
import be.atbash.ee.security.octopus.jwt.decoder.JWTDecoder;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.mp.token.MPJWTToken;
import be.atbash.ee.security.octopus.mp.token.MPToken;
import be.atbash.ee.security.octopus.token.AuthenticationToken;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 *
 */
@ApplicationScoped
public class MPUserFilter extends RestAuthenticatingFilter {

    @Inject
    private JWTDecoder jwtDecoder;

    @Inject
    private KeySelector keySelector;

    @Inject
    private MPBearerTokenVerifier verifier;

    @PostConstruct
    public void initInstance() {
        setName("mpUser"); // TODO Rename to authcMP or just mp (and then authcBasic becomes basic?
    }

    protected AuthenticationToken createToken(HttpServletRequest httpServletRequest, String token) {

        JWTData<MPJWTToken> data = jwtDecoder.decode(token, MPJWTToken.class, keySelector, verifier);
        return new MPToken(data.getData());

    }

    @Override
    protected boolean onAccessDenied(ServletRequest request, ServletResponse response) throws Exception {
        return executeLogin(request, response);
    }

}
