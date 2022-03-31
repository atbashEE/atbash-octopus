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
package be.atbash.ee.security.octopus.authz;

import be.atbash.ee.security.octopus.authc.CredentialValidationResultToken;
import be.atbash.ee.security.octopus.authz.permission.role.ApplicationRole;
import be.atbash.ee.security.octopus.realm.AuthorizationInfoBuilder;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;

import jakarta.enterprise.context.ApplicationScoped;

import static be.atbash.ee.security.octopus.OctopusConstants.INFO_KEY_TOKEN;

@ApplicationScoped
public class AuthorizationInfoProviderAdapter implements AuthorizationInfoProvider {
    @Override
    public AuthorizationInfo getAuthorizationInfo(PrincipalCollection principals) {
        UserPrincipal userPrincipal = principals.getPrimaryPrincipal();

        CredentialValidationResultToken token = userPrincipal.getUserInfo(INFO_KEY_TOKEN);

        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();
        // Define each 'callerGroup' as permission and as role. The RolePermissionResolver can be used to convert the role to a list of permissions.

        for (String callerGroup : token.getCallerGroups()) {
            builder.addRole(new ApplicationRole(callerGroup));
            builder.addPermission(callerGroup);
        }

        return builder.build();
    }
}
