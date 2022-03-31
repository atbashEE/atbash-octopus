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
package be.atbash.ee.security.octopus.authz.checks;

import be.atbash.ee.security.octopus.authz.Combined;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.permission.typesafe.RoleLookup;
import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
public class SecurityCheckRequiresRoles implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    private RoleLookup roleLookup;

    private Map<String, RolePermission> permissionCache;

    @PostConstruct
    public void init() {
        // StringPermissionProvider is optional.
        // TODO Check of the getOptionalBean
        roleLookup = CDIUtils.retrieveOptionalInstance(RoleLookup.class);

        permissionCache = new HashMap<>();
    }

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, SecurityCheckData securityCheckData) {
        SecurityCheckInfo result;

        if (!subject.isAuthenticated() && !subject.isRemembered()) {  // When login from remember me, the isAuthenticated return false
            result = SecurityCheckInfo.withException(
                    new SecurityAuthorizationViolationException("User required", infoProducer.getViolationInfo(accessContext))
            );
        } else {
            Set<SecurityViolation> securityViolations = performRoleChecks(securityCheckData, subject, accessContext);
            if (!securityViolations.isEmpty()) {
                result = SecurityCheckInfo.withException(
                        new SecurityAuthorizationViolationException(securityViolations));
            } else {
                result = SecurityCheckInfo.allowAccess();
            }
        }

        return result;
    }

    private Set<SecurityViolation> performRoleChecks(SecurityCheckData securityCheckData, Subject subject, AccessDecisionVoterContext accessContext) {
        Set<SecurityViolation> result = new HashSet<>();
        Combined permissionCombination = securityCheckData.getPermissionCombination();
        boolean onePermissionGranted = false;
        for (String roleName : securityCheckData.getValues()) {
            RolePermission namedRole = null;
            if (roleLookup != null) {
                namedRole = roleLookup.getRole(roleName);
            }
            if (namedRole == null) {
                namedRole = permissionCache.get(roleName);
                if (namedRole == null) {
                    namedRole = new RolePermission(roleName);
                    permissionCache.put(roleName, namedRole);
                }
            }
            if (subject.isPermitted(namedRole)) {
                onePermissionGranted = true;
            } else {
                OctopusInvocationContext invocationContext = accessContext.getSource();
                result.add(infoProducer.defineViolation(invocationContext, namedRole));
            }
        }
        // When we have specified OR and there is one permissions which didn't result in some violations
        // Remove all the collected violations since access is granted.
        if (permissionCombination == Combined.OR && onePermissionGranted) {
            result.clear();
        }
        return result;
    }

    @Override
    public SecurityCheckType getSecurityCheckType() {
        return SecurityCheckType.REQUIRES_ROLES;
    }
}
