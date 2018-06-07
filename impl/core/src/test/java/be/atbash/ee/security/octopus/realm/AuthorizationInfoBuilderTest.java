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
package be.atbash.ee.security.octopus.realm;

import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.WildcardPermission;
import be.atbash.ee.security.octopus.authz.permission.role.ApplicationRole;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermissionResolver;
import be.atbash.ee.security.octopus.authz.permission.typesafe.RoleLookup;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthorizationInfoBuilderTest {

    private BeanManagerFake beanManagerFake;

    @Mock
    private OctopusCoreConfiguration configurationMock;

    @Mock
    private RolePermissionResolver rolePermissionResolverMock;

    @Mock
    private RoleLookup roleLookupMock;

    @Before
    public void setup() {

        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(configurationMock, OctopusCoreConfiguration.class);

        when(configurationMock.isDynamicAuthorization()).thenReturn(Boolean.FALSE);
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void build() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        AuthorizationInfo info = builder.build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermission_simpleString() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        // simple permission as String will be translated by PermissionResolver
        AuthorizationInfo info = builder.addPermission("JUnit").build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(1);
        assertThat(info.getStringPermissions()).contains("JUnit");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermission_wildCard() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        AuthorizationInfo info = builder.addPermission("JUnit:*:*").build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(1);
        assertThat(info.getStringPermissions()).contains("JUnit:*:*");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermission_wildCardPermission() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        AuthorizationInfo info = builder.addPermission(new WildcardPermission("JUnit:*:*")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).hasSize(1);
        assertThat(info.getObjectPermissions()).contains(new WildcardPermission("JUnit:*:*"));
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermission_namedPermission() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        AuthorizationInfo info = builder.addPermission(new SimplePermission("JUnit")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(1);
        assertThat(info.getStringPermissions()).contains("JUnit");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermission_domainPermission() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        AuthorizationInfo info = builder.addPermission(new NamedDomainPermission("theName", "JUnit", "*", "*")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).hasSize(1);
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermission_multiple() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        AuthorizationInfo info = builder.addPermission("JUnit").addPermission("another").build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(2);
        assertThat(info.getStringPermissions()).contains("JUnit", "another");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermission_noDuplicates() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        AuthorizationInfo info = builder.addPermission("JUnit").addPermission("JUnit").build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(1);
        assertThat(info.getStringPermissions()).contains("JUnit");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermissions_stringPermission() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        List<String> permissions = new ArrayList<>();
        permissions.add("JUnit");
        permissions.add("anotherPermission");
        AuthorizationInfo info = builder.addStringPermissions(permissions).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(2);
        assertThat(info.getStringPermissions()).contains("JUnit", "anotherPermission");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermissions_stringPermissionNoDuplicates() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        List<String> permissions = new ArrayList<>();
        permissions.add("JUnit");
        permissions.add("anotherPermission");
        permissions.add("JUnit");
        AuthorizationInfo info = builder.addStringPermissions(permissions).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(2);
        assertThat(info.getStringPermissions()).contains("JUnit", "anotherPermission");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermissions_namedPermission() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        List<NamedPermission> permissions = new ArrayList<>();
        permissions.add(new SimplePermission("JUnit"));
        permissions.add(new SimplePermission("anotherPermission"));
        AuthorizationInfo info = builder.addNamedPermissions(permissions).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(2);
        assertThat(info.getStringPermissions()).contains("JUnit", "anotherPermission");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermissions_domainPermission() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        List<NamedDomainPermission> permissions = new ArrayList<>();
        permissions.add(new NamedDomainPermission("theName", "JUnit", "*", "*"));
        permissions.add(new NamedDomainPermission("other", "other", "*", "*"));
        AuthorizationInfo info = builder.addPermissions(permissions).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).hasSize(2);
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermissions_noDuplicates() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        List<NamedPermission> permissions = new ArrayList<>();
        permissions.add(new SimplePermission("JUnit"));
        permissions.add(new SimplePermission("JUnit"));
        AuthorizationInfo info = builder.addNamedPermissions(permissions).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).hasSize(1);
        assertThat(info.getStringPermissions()).contains("JUnit");
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addRole_static() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        // static, no rolePermissionResolver, no roleLookup
        AuthorizationInfo info = builder.addRole(new ApplicationRole("JUnit")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).hasSize(1);
        assertThat(info.getObjectPermissions()).containsOnly(new RolePermission("JUnit"));
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addRole_static_RolePermissionResolver() {
        beanManagerFake.registerBean(rolePermissionResolverMock, RolePermissionResolver.class);
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        List<Permission> permissions = new ArrayList<>();
        permissions.add(new NamedDomainPermission("perm1", "perm:1:*"));
        permissions.add(new NamedDomainPermission("perm2", "perm:2:*"));
        when(rolePermissionResolverMock.resolvePermissionsInRole("JUnit")).thenReturn(permissions);

        // static, rolePermissionResolver, no roleLookup
        AuthorizationInfo info = builder.addRole(new ApplicationRole("JUnit")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).hasSize(2);
        assertThat(info.getObjectPermissions()).extracting("name").containsOnly("perm1", "perm2");
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addRole_static_RoleLookup() {

        beanManagerFake.registerBean(roleLookupMock, RoleLookup.class);
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        RolePermission applicationRole = new RolePermission("MappedRole");
        when(roleLookupMock.getRole("JUnit")).thenReturn(applicationRole);

        // static, rolePermissionResolver, no roleLookup
        AuthorizationInfo info = builder.addRole(new ApplicationRole("JUnit")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).hasSize(1);
        assertThat(info.getObjectPermissions()).contains(new RolePermission("MappedRole"));
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addRole_dynamic() {
        beanManagerFake.endRegistration();
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        when(configurationMock.isDynamicAuthorization()).thenReturn(Boolean.TRUE);
        // dynamic
        AuthorizationInfo info = builder.addRole(new ApplicationRole("JUnit")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).hasSize(1);
        assertThat(info.getRoles()).containsOnly("JUnit");
    }

    private static class SimplePermission implements NamedPermission {

        private String name;

        public SimplePermission(String name) {
            this.name = name;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public boolean implies(Permission permission) {
            return permission instanceof SimplePermission && permission.equals(this);
        }

        @Override
        public String toJSONString() {
            // Not important here
            return null;
        }
    }

}