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
package be.atbash.ee.security.octopus.authz.permission;

import be.atbash.ee.security.octopus.ShiroEquivalent;
import be.atbash.ee.security.octopus.authz.permission.typesafe.PermissionLookup;
import be.atbash.util.CDIUtils;
import be.atbash.util.Reviewed;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;

/**
 * A {@code PermisisonResolver} resolves a String value and converts it into a
 * {@link Permission Permission} instance.
 * <p/>
 * The default should be suitable for most purposes, which constructs {@link WildcardPermission} objects when no match is found by any lookup .
 * However, any resolver may be configured (in the CDI environment, not with Java SE) if an application wishes to use different
 * {@link Permission} implementations.
 * <p/>
 * A {@code PermissionResolver} is used by many Octopus components such as annotations, ini file
 * configuration, URL configuration, etc.  It is useful whenever a String representation of a permission is specified
 * and that String needs to be converted to a Permission instance before executing a security check.
 * <p/>
 * Octopus chooses to support {@link WildcardPermission Wildcardpermission}s by default in almost all components.   One of the nice
 * things about {@code WildcardPermission}s being supported by default is that it makes it very easy to
 * store complex permissions in the database - and also makes it very easy to represent permissions in JSF files,
 * annotations, etc., where a simple string representation is useful.
 * <p/>
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.authz.permission.PermissionResolver"})
@ApplicationScoped
// Code of be.c4j.ee.security.permission.OctopusPermissionResolver is included here
@Reviewed
public class PermissionResolver {

    private PermissionLookup permissionLookup;

    private StringPermissionLookup stringLookup;

    /**
     * Used in the CDI case in combination with init method PostConstruct.
     */
    public PermissionResolver() {
    }

    /**
     * Used in plain Java SE environment.
     *
     * @param permissionLookup
     * @param stringLookup
     */
    public PermissionResolver(PermissionLookup permissionLookup, StringPermissionLookup stringLookup) {
        this.permissionLookup = permissionLookup;
        this.stringLookup = stringLookup;
    }

    @PostConstruct
    public void init() {
        permissionLookup = CDIUtils.retrieveOptionalInstance(PermissionLookup.class);
        stringLookup = CDIUtils.retrieveOptionalInstance(StringPermissionLookup.class);
    }

    public Permission resolvePermission(String permissionString) {
        Permission permission;
        if (permissionLookup == null && stringLookup == null) {
            if (permissionString.contains(":")) {
                permission = new WildcardPermission(permissionString);
            } else {
                permission = new WildcardPermission(permissionString + ":*:*");
            }
        } else {
            if (permissionLookup != null) {
                permission = permissionLookup.getPermission(permissionString);
            } else {
                permission = stringLookup.getPermission(permissionString);
            }
        }
        return permission;
    }
}
