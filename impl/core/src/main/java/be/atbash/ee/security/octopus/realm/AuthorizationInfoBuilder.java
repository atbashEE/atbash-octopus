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
import be.atbash.ee.security.octopus.authz.SimpleAuthorizationInfo;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.role.ApplicationRole;
import be.atbash.ee.security.octopus.authz.permission.role.NamedRole;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermissionResolver;
import be.atbash.ee.security.octopus.authz.permission.typesafe.RoleLookup;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.util.CDIUtils;
import be.atbash.util.PublicAPI;

import javax.enterprise.inject.Typed;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 *
 */
@Typed
@PublicAPI
public class AuthorizationInfoBuilder {

    private RoleLookup roleLookup;
    private RolePermissionResolver rolePermissionResolver;
    private OctopusCoreConfiguration config;

    private Set<Permission> permissions = new HashSet<>();
    private Set<String> stringPermissions = new HashSet<>();
    private Set<String> stringRoles = new HashSet<>();

    public AuthorizationInfoBuilder() {
        roleLookup = CDIUtils.retrieveOptionalInstance(RoleLookup.class);
        rolePermissionResolver = CDIUtils.retrieveOptionalInstance(RolePermissionResolver.class);
        config = CDIUtils.retrieveInstance(OctopusCoreConfiguration.class);
    }

    public AuthorizationInfoBuilder addPermission(NamedPermission namedPermission) {
        if (namedPermission instanceof NamedDomainPermission) {
            permissions.add((NamedDomainPermission) namedPermission);
        } else {
            addPermission(namedPermission.name());
        }
        return this;
    }

    public AuthorizationInfoBuilder addPermission(String permissionName) {
        stringPermissions.add(permissionName);
        return this;
    }

    public AuthorizationInfoBuilder addNamedPermissions(Collection<? extends NamedPermission> namedPermissions) {
        for (NamedPermission namedPermission : namedPermissions) {
            addPermission(namedPermission);
        }
        return this;
    }

    public AuthorizationInfoBuilder addStringPermissions(Collection<String> permissions) {
        stringPermissions.addAll(permissions);
        return this;
    }

    public AuthorizationInfoBuilder addPermissions(Collection<? extends Permission> permissions) {
        this.permissions.addAll(permissions);
        return this;
    }

    public AuthorizationInfoBuilder addRole(NamedRole namedRole) {

        if (config.isDynamicAuthorization()) {
            addRoleDynamicSituation(namedRole);
        } else {
            addRoleStaticSituation(namedRole);

        }
        return this;
    }

    private void addRoleDynamicSituation(NamedRole namedRole) {
        stringRoles.add(namedRole.name());
    }

    public AuthorizationInfoBuilder addRole(String roleName) {

        addRole(new ApplicationRole(roleName));

        return this;
    }

    private void addRoleStaticSituation(NamedRole namedRole) {
        boolean resolved = false;
        if (rolePermissionResolver != null) {
            Collection<Permission> permissions = rolePermissionResolver.resolvePermissionsInRole(namedRole.name());
            if (permissions != null && !permissions.isEmpty()) {
                this.permissions.addAll(permissions);
                resolved = true;
            }
        }

        if (!resolved) {
            if (roleLookup == null) {
                // No roleLookup specified, use the default logic.
                permissions.add(new RolePermission(namedRole.name()));
            } else {
                permissions.add(roleLookup.getRole(namedRole.name()));
            }
        }
    }

    public AuthorizationInfoBuilder addRoles(Collection<? extends NamedRole> namedRoles) {
        for (NamedRole namedRole : namedRoles) {
            addRole(namedRole);
        }
        return this;
    }

    public AuthorizationInfoBuilder addRolesByName(Collection<String> rolesNames) {
        for (String roleName : rolesNames) {
            addRole(new ApplicationRole(roleName));
        }
        return this;
    }

    public AuthorizationInfo build() {
        SimpleAuthorizationInfo result = new SimpleAuthorizationInfo();
        result.addObjectPermissions(permissions);
        result.addStringPermissions(stringPermissions);
        result.addRoles(stringRoles);
        return result;
    }

}
