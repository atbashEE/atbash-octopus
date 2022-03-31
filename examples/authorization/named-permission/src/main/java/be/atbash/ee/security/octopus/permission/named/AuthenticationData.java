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
package be.atbash.ee.security.octopus.permission.named;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.annotation.OnlyDuringAuthentication;
import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.realm.AuthorizationInfoBuilder;
import be.atbash.ee.security.octopus.realm.SecurityDataProvider;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class AuthenticationData extends SecurityDataProvider {

    private int principalId = 0;

    @Override
    @OnlyDuringAuthentication
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {

        if (token instanceof UsernamePasswordToken) {
            UsernamePasswordToken usernamePasswordToken = (UsernamePasswordToken) token;

            AuthenticationInfoBuilder authenticationInfoBuilder = new AuthenticationInfoBuilder();
            authenticationInfoBuilder.principalId(principalId++).name(token.getPrincipal().toString());
            authenticationInfoBuilder.userName(token.getPrincipal().toString());
            authenticationInfoBuilder.password(usernamePasswordToken.getUsername());

            return authenticationInfoBuilder.build();
        }
        return null;
    }

    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {
        AuthorizationInfoBuilder infoBuilder = new AuthorizationInfoBuilder();
        UserPrincipal userPrincipal = principals.getPrimaryPrincipal();
        if ("test".equals(userPrincipal.getUserName())) {
            infoBuilder.addPermission("special");
        }
        return infoBuilder.build();
    }
}
