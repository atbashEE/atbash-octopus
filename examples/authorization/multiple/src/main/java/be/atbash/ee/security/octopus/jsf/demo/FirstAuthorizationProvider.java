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
package be.atbash.ee.security.octopus.jsf.demo;

import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.AuthorizationInfoProvider;
import be.atbash.ee.security.octopus.realm.AuthorizationInfoBuilder;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;

import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class FirstAuthorizationProvider implements AuthorizationInfoProvider {
    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
        UserPrincipal principal = principals.getPrimaryPrincipal();
        if ("test".equalsIgnoreCase(principal.getUserName())) {
            builder.addPermission("demo:read:*");
        }

        return builder.build();

    }
}
