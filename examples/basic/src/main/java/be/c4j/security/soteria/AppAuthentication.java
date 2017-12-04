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
package be.c4j.security.soteria;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.SimpleAuthorizationInfo;
import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.realm.SecurityDataProvider;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;

import javax.enterprise.context.ApplicationScoped;


@ApplicationScoped
public class AppAuthentication implements SecurityDataProvider {

    private int principalId = 0;

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof UsernamePasswordToken) {
            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(principalId++).name(token.getPrincipal().toString());
            // TODO: Change for production. Here we use username as password
            authenticationInfoBuilder.password(usernamePasswordToken.getUsername());

            return authenticationInfoBuilder.build();
        }
        return null;
    }


    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {

        // TODO: Change for production. Principal has no assigned no permission not roles.
        return new SimpleAuthorizationInfo();
    }

}
