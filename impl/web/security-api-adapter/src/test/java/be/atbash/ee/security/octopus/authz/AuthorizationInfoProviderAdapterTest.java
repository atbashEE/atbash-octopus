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

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.authc.CredentialValidationResultToken;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import javax.security.enterprise.identitystore.CredentialValidationResult;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import static be.atbash.ee.security.octopus.OctopusConstants.INFO_KEY_TOKEN;
import static org.assertj.core.api.Assertions.assertThat;

public class AuthorizationInfoProviderAdapterTest {

    @AfterEach
    public void cleanup() {
        TestConfig.resetConfig();
    }

    @Test
    public void getAuthorizationInfo() {
        System.setProperty("atbash.utils.cdi.check", "noCDI");
        AuthorizationInfoProviderAdapter adapter = new AuthorizationInfoProviderAdapter();

        UserPrincipal userPrincipal = new UserPrincipal("Id", "junit", "JUnit");

        Set<String> groups = new HashSet<>();
        groups.add("group1");
        groups.add("group2");
        CredentialValidationResult validationResult = new CredentialValidationResult("JUnit Caller", groups);
        CredentialValidationResultToken token = new CredentialValidationResultToken(validationResult);

        userPrincipal.addUserInfo(INFO_KEY_TOKEN, token);
        PrincipalCollection principals = new PrincipalCollection(userPrincipal);
        AuthorizationInfo info = adapter.getAuthorizationInfo(principals);
        assertThat(info.getRoles()).isEmpty();
        assertThat(info.getStringPermissions()).containsOnly("group1", "group2");

        Collection<Permission> permissions = info.getObjectPermissions();
        assertThat(permissions).hasSize(2);
        assertThat(permissions.iterator().next()).isInstanceOf(RolePermission.class);

        Set<String> roles = new HashSet<>();
        for (Permission permission : permissions) {
            RolePermission rolePermission = (RolePermission) permission;
            roles.add(rolePermission.getRoleName());
        }
        assertThat(roles).containsOnly("group1", "group2");
    }
}