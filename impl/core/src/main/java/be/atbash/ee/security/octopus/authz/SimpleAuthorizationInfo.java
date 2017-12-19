/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authz.permission.Permission;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

/**
 * Simple POJO implementation of the {@link AuthorizationInfo} interface that stores roles and permissions as internal
 * attributes.
 *
 * @see org.apache.shiro.realm.AuthorizingRealm
 */
// FIXME Rename to ??DefaultAuthorizationInfo??
// or remove the interface?
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authz.SimpleAuthorizationInfo"})
public class SimpleAuthorizationInfo implements AuthorizationInfo {

    /**
     * The internal roles collection.
     */
    protected Set<String> roles;

    /**
     * Collection of all string-based permissions associated with the account.
     */
    protected Set<String> stringPermissions;

    /**
     * Collection of all object-based permissions associaed with the account.
     */
    protected Set<Permission> objectPermissions;

    /**
     * Default no-argument constructor.
     */
    public SimpleAuthorizationInfo() {
    }

    /**
     * Creates a new instance with the specified roles and no permissions.
     *
     * @param roles the roles assigned to the realm account.
     */
    public SimpleAuthorizationInfo(Set<String> roles) {
        this.roles = roles;
    }

    public Set<String> getRoles() {
        return roles;
    }

    /**
     * Sets the roles assigned to the account.
     *
     * @param roles the roles assigned to the account.
     */
    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    /**
     * Adds (assigns) a role to those associated with the account.  If the account doesn't yet have any roles, a
     * new roles collection (a Set) will be created automatically.
     *
     * @param role the role to add to those associated with the account.
     */
    public void addRole(String role) {
        if (roles == null) {
            roles = new HashSet<>();
        }
        roles.add(role);
    }

    /**
     * Adds (assigns) multiple roles to those associated with the account.  If the account doesn't yet have any roles, a
     * new roles collection (a Set) will be created automatically.
     *
     * @param roles the roles to add to those associated with the account.
     */
    public void addRoles(Collection<String> roles) {
        if (this.roles == null) {
            this.roles = new HashSet<>();
        }
        this.roles.addAll(roles);
    }

    public Set<String> getStringPermissions() {
        return stringPermissions;
    }

    /**
     * Sets the string-based permissions assigned directly to the account.  The permissions set here, in addition to any
     * {@link #getObjectPermissions() object permissions} constitute the total permissions assigned directly to the
     * account.
     *
     * @param stringPermissions the string-based permissions assigned directly to the account.
     */
    public void setStringPermissions(Set<String> stringPermissions) {
        this.stringPermissions = stringPermissions;
    }

    /**
     * Adds (assigns) a permission to those directly associated with the account.  If the account doesn't yet have any
     * direct permissions, a new permission collection (a Set&lt;String&gt;) will be created automatically.
     *
     * @param permission the permission to add to those directly assigned to the account.
     */
    public void addStringPermission(String permission) {
        if (stringPermissions == null) {
            stringPermissions = new HashSet<>();
        }
        stringPermissions.add(permission);
    }

    /**
     * Adds (assigns) multiple permissions to those associated directly with the account.  If the account doesn't yet
     * have any string-based permissions, a  new permissions collection (a Set&lt;String&gt;) will be created automatically.
     *
     * @param permissions the permissions to add to those associated directly with the account.
     */
    public void addStringPermissions(Collection<String> permissions) {
        if (stringPermissions == null) {
            stringPermissions = new HashSet<>();
        }
        stringPermissions.addAll(permissions);
    }

    public Set<Permission> getObjectPermissions() {
        return objectPermissions;
    }

    /**
     * Sets the object-based permissions assigned directly to the account.  The permissions set here, in addition to any
     * {@link #getStringPermissions() string permissions} constitute the total permissions assigned directly to the
     * account.
     *
     * @param objectPermissions the object-based permissions assigned directly to the account.
     */
    public void setObjectPermissions(Set<Permission> objectPermissions) {
        this.objectPermissions = objectPermissions;
    }

    /**
     * Adds (assigns) a permission to those directly associated with the account.  If the account doesn't yet have any
     * direct permissions, a new permission collection (a Set&lt;{@link Permission Permission}&gt;) will be created automatically.
     *
     * @param permission the permission to add to those directly assigned to the account.
     */
    public void addObjectPermission(Permission permission) {
        if (objectPermissions == null) {
            objectPermissions = new HashSet<>();
        }
        objectPermissions.add(permission);
    }

    /**
     * Adds (assigns) multiple permissions to those associated directly with the account.  If the account doesn't yet
     * have any object-based permissions, a  new permissions collection (a Set&lt;{@link Permission Permission}&gt;)
     * will be created automatically.
     *
     * @param permissions the permissions to add to those associated directly with the account.
     */
    public void addObjectPermissions(Collection<Permission> permissions) {
        if (objectPermissions == null) {
            objectPermissions = new HashSet<>();
        }
        objectPermissions.addAll(permissions);
    }
}
