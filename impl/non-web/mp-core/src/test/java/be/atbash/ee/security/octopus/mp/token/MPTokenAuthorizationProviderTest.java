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
package be.atbash.ee.security.octopus.mp.token;

import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.WildcardPermission;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermissionResolver;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.token.AuthorizationToken;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class MPTokenAuthorizationProviderTest {

    private BeanManagerFake beanManagerFake;

    @Mock
    private OctopusCoreConfiguration coreConfigurationMock;

    @Mock
    private RolePermissionResolver rolePermissionResolverMock;

    private MPTokenAuthorizationProvider provider;

    @BeforeEach
    public void test() {
        provider = new MPTokenAuthorizationProvider();

        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(coreConfigurationMock, OctopusCoreConfiguration.class);
    }

    @AfterEach
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void getAuthorizationInfo() {
        beanManagerFake.endRegistration();
        when(coreConfigurationMock.isDynamicAuthorization()).thenReturn(false);

        MPJWTToken mpjwtToken = new MPJWTToken();
        List<String> groups = Arrays.asList("group1", "group2");
        mpjwtToken.setGroups(groups);
        AuthorizationToken token = new MPToken(mpjwtToken);
        AuthorizationInfo authorizationInfo = provider.getAuthorizationInfo(token);

        assertThat(authorizationInfo).isNotNull();
        assertThat(authorizationInfo.getObjectPermissions()).hasSize(2);
        assertThat(authorizationInfo.getObjectPermissions().iterator().next()).isInstanceOf(RolePermission.class);
    }

    @Test
    public void getAuthorizationInfo_usesResolver() {
        beanManagerFake.registerBean(rolePermissionResolverMock, RolePermissionResolver.class);

        beanManagerFake.endRegistration();
        when(coreConfigurationMock.isDynamicAuthorization()).thenReturn(false);

        Collection<Permission> permissions1 = new ArrayList<>();
        permissions1.add(new WildcardPermission("group1:*:*"));
        when(rolePermissionResolverMock.resolvePermissionsInRole("group1")).thenReturn(permissions1);

        Collection<Permission> permissions2 = new ArrayList<>();
        permissions2.add(new WildcardPermission("group2:a:*"));
        permissions2.add(new WildcardPermission("group2:b:*"));
        when(rolePermissionResolverMock.resolvePermissionsInRole("group2")).thenReturn(permissions2);

        MPJWTToken mpjwtToken = new MPJWTToken();
        List<String> groups = Arrays.asList("group1", "group2");
        mpjwtToken.setGroups(groups);
        AuthorizationToken token = new MPToken(mpjwtToken);
        AuthorizationInfo authorizationInfo = provider.getAuthorizationInfo(token);

        assertThat(authorizationInfo).isNotNull();
        assertThat(authorizationInfo.getObjectPermissions()).hasSize(3);
        assertThat(authorizationInfo.getObjectPermissions().iterator().next()).isInstanceOf(WildcardPermission.class);
    }
}