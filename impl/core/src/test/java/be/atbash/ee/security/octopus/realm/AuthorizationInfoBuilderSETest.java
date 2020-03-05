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
package be.atbash.ee.security.octopus.realm;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.authz.AuthorizationInfo;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.WildcardPermission;
import be.atbash.ee.security.octopus.authz.permission.role.ApplicationRole;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.realm.mocks.FakeRoleMapperProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class AuthorizationInfoBuilderSETest {

    @BeforeEach
    public void setup() {

        System.setProperty("atbash.utils.cdi.check", "false");
    }

    @AfterEach
    public void teardown() {
        TestConfig.resetConfig();
        System.clearProperty("atbash.utils.cdi.check");
    }

    @Test
    public void build() {
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        AuthorizationInfo info = builder.build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermission_simpleString() {
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
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        AuthorizationInfo info = builder.addPermission(new NamedDomainPermission("theName", "JUnit", "*", "*")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).hasSize(1);
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addPermission_multiple() {
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
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        // static, rolePermissionResolver, no roleLookup
        AuthorizationInfo info = builder.addRole(new ApplicationRole("roleToResolve")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).hasSize(2);
        assertThat(info.getObjectPermissions()).extracting("name").containsOnly("perm1", "perm2");
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addRole_static_RoleLookup() {
        FakeRoleMapperProvider.defineRoleLookup = true;
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        // static, no rolePermissionResolver,  roleLookup
        AuthorizationInfo info = builder.addRole(new ApplicationRole("JUnit")).build();
        assertThat(info).isNotNull();
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).hasSize(1);
        assertThat(info.getObjectPermissions()).contains(new RolePermission("MappedRole"));
        assertThat(info.getRoles()).isEmpty();
    }

    @Test
    public void addRole_dynamic() {
        AuthorizationInfoBuilder builder = new AuthorizationInfoBuilder();

        TestConfig.addConfigValue("authorization.dynamic", "true");
        TestConfig.registerDefaultConverters();

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

        public String toJSONString() {
            // Not important here
            return null;
        }
    }

}