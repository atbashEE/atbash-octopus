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
package be.atbash.ee.security.octopus.authz.permission.role;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.util.PublicAPI;
import be.atbash.util.Reviewed;

import java.util.Collection;

/**
 * A RolePermissionResolver resolves a String value and converts it into a Collection of
 * {@link Permission} instances.
 * <p/>
 * In some cases a {@link be.atbash.ee.security.octopus.authz.AuthorizationInfoProvider} may only be given  a list of roles.
 * This component allows to resolve the roles into permissions.
 * <p>
 * ??An implementation as CDI bean is not required. The the roles supplied to AuthorizationInfoProvider as role and there
 * is no conversion to permissions.??
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authz.permission.RolePermissionResolver"})
@PublicAPI
@Reviewed
public interface RolePermissionResolver {

    /**
     * Resolves a Collection of Permissions based on the given String representation.
     *
     * @param roleString the String representation of a role name to resolve.
     * @return a Collection of Permissions based on the given String representation or empty Collection if no mapping to permission is needed.
     */
    Collection<Permission> resolvePermissionsInRole(String roleString);

}
