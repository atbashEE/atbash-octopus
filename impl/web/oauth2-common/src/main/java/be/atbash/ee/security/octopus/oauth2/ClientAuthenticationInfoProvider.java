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
package be.atbash.ee.security.octopus.oauth2;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.authc.AuthenticationStrategy;
import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.order.ProviderOrder;

import jakarta.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
@ProviderOrder(-10)
public class ClientAuthenticationInfoProvider extends AuthenticationInfoProvider {

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        if (token instanceof OAuth2UserToken) {
            // For the Web use case
            OAuth2UserToken oAuth2UserToken = (OAuth2UserToken) token;

            builder.principalId(oAuth2UserToken.getId());

            builder.name(oAuth2UserToken.getName());
            builder.token(oAuth2UserToken);

            return builder.build();

        }
        return null;
    }

    @Override
    public AuthenticationStrategy getAuthenticationStrategy() {
        return AuthenticationStrategy.SUFFICIENT;
    }
}
