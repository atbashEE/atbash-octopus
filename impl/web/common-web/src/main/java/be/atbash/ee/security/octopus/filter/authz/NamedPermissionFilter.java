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
import be.atbash.ee.security.octopus.authz.permission.PermissionResolver;
import be.atbash.ee.security.octopus.subject.WebSubject;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.util.ArrayList;
import java.util.List;

import static be.atbash.ee.security.octopus.OctopusConstants.OCTOPUS_VIOLATION_MESSAGE;

@ApplicationScoped
public class NamedPermissionFilter extends AuthorizationFilter {

    @Inject
    private PermissionResolver permissionResolver;

    @PostConstruct
    public void initInstance() {
        setName("np");
        setName("namedPermission");

    }

    @Override
    protected boolean isAccessAllowed(ServletRequest request, ServletResponse response) throws
            Exception {
        WebSubject subject = getSubject();

        String[] pathConfig = getPathConfig(request);

        boolean permitted = true;
        List<Permission> violatedPermissions = new ArrayList<>();
        for (String permissionName : pathConfig) {

            Permission permission = permissionResolver.resolvePermission(permissionName);
            if (!subject.isPermitted(permission)) {
                permitted = false;
                violatedPermissions.add(permission);
            }
        }
        if (!permitted) {
            // FIXME this is also required for voters.
            // Need to have something predefined so that it can be used in custom voters.
            defineViolationMessage(request, violatedPermissions);
        }

        return permitted;
    }

    private void defineViolationMessage(ServletRequest request, List<Permission> violatedPermissions) {
        // FIXME Duplicate (almost ) at be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException.SecurityAuthorizationViolationException(java.util.Set<org.apache.deltaspike.security.api.authorization.SecurityViolation>)

        StringBuilder violations = new StringBuilder();
        violations.append("Violation of Permission ");
        boolean first = true;

        for (Permission violatedPermission : violatedPermissions) {
            if (!first) {
                violations.append(" - ");
            }
            violations.append(violatedPermission.toString());
            first = false;
        }

        request.setAttribute(OCTOPUS_VIOLATION_MESSAGE, violations.toString());
    }

    @Override
    protected boolean requiresPathConfiguration() {
        return true;
    }

}
