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
package be.atbash.ee.security.octopus.keycloak.adapter;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.TokenBasedAuthorizationInfoProvider;
import be.atbash.ee.security.octopus.token.AuthorizationToken;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class KeycloakUserTokenAuthorizationProviderTest {

    private KeycloakUserTokenAuthorizationProvider authorizationProvider = new KeycloakUserTokenAuthorizationProvider();

    @Before
    public void setup() {

        System.setProperty("atbash.utils.cdi.check", "false");
    }

    @After
    public void teardown() {
        TestConfig.resetConfig();
    }

    @Test
    public void getAuthorizationInfo() {
        KeycloakUserToken token = KeycloakUserToken.fromIdToken(new AccessTokenResponse(), new IDToken());
        Set<String> roles = new HashSet<>();
        roles.add("role1");
        roles.add("role2");
        token.setRoles(roles);
        AuthorizationInfo authorizationInfo = authorizationProvider.getAuthorizationInfo(token);

        assertThat(authorizationInfo).isNotNull();
        assertThat(authorizationInfo.getRoles()).isEmpty();  // By default within AuthorizationInfoBuilder, roles are defined as RolePermission
        assertThat(authorizationInfo.getObjectPermissions()).hasSize(2);
        assertThat(authorizationInfo.getObjectPermissions()).extracting("roleName").contains("role1", "role2");

    }

    @Test
    public void getAuthorizationInfo_emptySet() {
        KeycloakUserToken token = KeycloakUserToken.fromIdToken(new AccessTokenResponse(), new IDToken());
        token.setRoles(new HashSet<String>());
        AuthorizationInfo authorizationInfo = authorizationProvider.getAuthorizationInfo(token);

        assertThat(authorizationInfo).isNotNull();
        assertThat(authorizationInfo.getRoles()).isEmpty();  // By default within AuthorizationInfoBuilder, roles are defined as RolePermission
        assertThat(authorizationInfo.getObjectPermissions()).isEmpty();

    }

    @Test
    public void getAuthorizationInfo_WrongToken() {
        AuthorizationInfo authorizationInfo = authorizationProvider.getAuthorizationInfo(new AuthorizationToken() {
            @Override
            public Class<? extends TokenBasedAuthorizationInfoProvider> authorizationProviderClass() {
                return null;
            }
        });

        assertThat(authorizationInfo).isNull();

    }
}