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
package be.atbash.ee.security.octopus.filter.authz;

import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.role.NamedRole;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.permission.typesafe.RoleLookup;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.CDIUtils;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

/**
 *
 */
@ApplicationScoped
public class NamedRoleOneFilter extends AuthorizationFilter {

    private RoleLookup<? extends NamedRole> roleLookup;

    @PostConstruct
    public void initInstance() {
        setName("nr1");
        setName("namedRole1");
        roleLookup = CDIUtils.retrieveOptionalInstance(RoleLookup.class);

    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response) throws
            Exception {
        Subject subject = getSubject();

        String[] pathConfig = getPathConfig(request);

        boolean permitted = false;
        for (String role : pathConfig) {
            if (subject.isPermitted(getRolePermission(role))) {
                permitted = true;
            }
        }
        return permitted;
    }

    private Permission getRolePermission(String role) {
        Permission result;

        if (roleLookup == null) {
            // TODO Should we cache these instances somewhere? (memory improvement)
            result = new RolePermission(role);
        } else {
            result = roleLookup.getRole(role);
        }
        return result;
    }

}
