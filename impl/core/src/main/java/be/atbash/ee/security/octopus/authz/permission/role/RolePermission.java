/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.authz.permission.role;

import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.util.StringUtils;
import be.atbash.util.exception.AtbashIllegalActionException;

import java.util.Objects;

/**
 * A permission that act as a role where only the name is important (no domain concepts like the
 * {@link be.atbash.ee.security.octopus.authz.permission.DomainPermission}) With authorization, a role must be matched exactly
 * before access is granted.
 * This class is used internally and should never be used by the developer.
 */
public class RolePermission implements Permission, NamedPermission {

    private String roleName;

    public RolePermission(String roleName) {
        if (StringUtils.isEmpty(roleName)) {
            throw new AtbashIllegalActionException("Role name can't be null or empty");
        }
        this.roleName = roleName;
    }

    @Override
    public String name() {
        return roleName;
    }

    @Override
    public boolean implies(Permission p) {
        // By default only supports comparisons with other NamedApplicationRole
        if (!(p instanceof RolePermission)) {
            return false;
        }
        RolePermission otherRole = (RolePermission) p;
        return roleName.equals(otherRole.roleName);
    }

    public String getRoleName() {
        return roleName;
    }

    @Override
    public String toJSONString() {
        // FIXME
        throw new UnsupportedOperationException("TODO Implement");
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RolePermission)) {
            return false;
        }

        RolePermission that = (RolePermission) o;

        return Objects.equals(roleName, that.roleName);
    }

    @Override
    public final int hashCode() {
        return roleName != null ? roleName.hashCode() : 0;
    }

    @Override
    public String toString() {
        return ">" + roleName + "<";
    }
}
