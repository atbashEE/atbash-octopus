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
package be.atbash.ee.security.octopus.realm.mocks;

import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermissionResolver;

import java.util.*;

/**
 *
 */

public class RolePermissionResolverMock implements RolePermissionResolver {

    private Map<String, List<Permission>> mapping = new HashMap<>();

    public RolePermissionResolverMock() {

        List<Permission> permissions = new ArrayList<>();
        permissions.add(new NamedDomainPermission("perm1", "perm:1:*"));
        permissions.add(new NamedDomainPermission("perm2", "perm:2:*"));
        mapping.put("roleToResolve", permissions);

    }

    @Override
    public Collection<Permission> resolvePermissionsInRole(String roleString) {

        return mapping.get(roleString);
    }
}
