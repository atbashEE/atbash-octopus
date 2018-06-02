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

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.mp.token.MPToken;
import be.atbash.ee.security.octopus.util.order.ProviderOrder;

import javax.enterprise.context.ApplicationScoped;
import java.util.UUID;

/**
 *
 */
@ProviderOrder(20)
@ApplicationScoped
public class MPTokenAuthenticationInfoProvider implements AuthenticationInfoProvider {

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof MPToken) {

            MPToken mpToken = (MPToken) token;

            AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();

            if (mpToken.getId() == null) {
                builder.principalId(UUID.randomUUID().toString());
            } else {
                builder.principalId(mpToken.getId());
            }
            builder.name(mpToken.getPrincipal().toString());
            builder.token(mpToken);
            return builder.build();

        }
        return null;

    }
}
