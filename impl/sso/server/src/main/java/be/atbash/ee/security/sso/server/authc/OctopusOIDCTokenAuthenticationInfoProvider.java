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
package be.atbash.ee.security.sso.server.authc;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.authc.AuthenticationStrategy;
import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.order.ProviderOrder;
import be.atbash.ee.security.sso.server.token.OIDCEndpointToken;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
@ProviderOrder(value = -100)
public class OctopusOIDCTokenAuthenticationInfoProvider extends AuthenticationInfoProvider {
    @Override
    protected AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (token instanceof OIDCEndpointToken) {
            OIDCEndpointToken oidcEndpointToken = (OIDCEndpointToken) token;
            AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
            builder.userName(oidcEndpointToken.getClientId().getValue())
                    .principalId(oidcEndpointToken.getClientId().getValue());
            return builder.build();
        }
        return null;
    }

    @Override
    public AuthenticationStrategy getAuthenticationStrategy() {
        return AuthenticationStrategy.SUFFICIENT;
    }
}
