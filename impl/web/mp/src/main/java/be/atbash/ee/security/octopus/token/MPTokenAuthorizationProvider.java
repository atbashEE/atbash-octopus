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
package be.atbash.ee.security.octopus.token;

import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.TokenBasedAuthorizationInfoProvider;
import be.atbash.ee.security.octopus.realm.AuthorizationInfoBuilder;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class MPTokenAuthorizationProvider implements TokenBasedAuthorizationInfoProvider {

    @Override
    public AuthorizationInfo getAuthorizationInfo(AuthorizationToken token) {
        if (token instanceof MPToken) {
            MPToken mpToken = (MPToken) token;
            AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
            for (String group : mpToken.getJWT().getGroups()) {

                builder.addRole(group);
            }

            return builder.build();
        } else {
            return null;
        }

    }

}
