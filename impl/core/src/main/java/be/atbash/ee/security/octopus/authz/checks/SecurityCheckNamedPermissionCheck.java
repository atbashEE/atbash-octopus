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
import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.voter.GenericPermissionVoter;
import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.names.VoterNameFactory;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.HashSet;
import java.util.Set;

/**
 * SecurityCheck for the annotation defined by OctopusConfig.getNamedPermissionCheckClass()
 */
@ApplicationScoped
public class SecurityCheckNamedPermissionCheck implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Inject
    private OctopusCoreConfiguration config;

    @Inject
    private VoterNameFactory nameFactory;

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, SecurityCheckData securityCheckData) {
        SecurityCheckInfo result;

        if (!subject.isAuthenticated() && !subject.isRemembered()) {  // When login from remember me, the isAuthenticated return false
            result = SecurityCheckInfo.withException(
                    new SecurityAuthorizationViolationException("User required", infoProducer.getViolationInfo(accessContext))
            );
        } else {
            Set<SecurityViolation> securityViolations = performNamedPermissionChecks(securityCheckData, accessContext);
            if (!securityViolations.isEmpty()) {
                result = SecurityCheckInfo.withException(
                        new SecurityAuthorizationViolationException(securityViolations));
            } else {
                result = SecurityCheckInfo.allowAccess();
            }
        }

        return result;
    }

    private Set<SecurityViolation> performNamedPermissionChecks(SecurityCheckData securityCheckData, AccessDecisionVoterContext context) {
        Set<SecurityViolation> result = new HashSet<>();

        Combined permissionCombination = securityCheckData.getPermissionCombination();
        boolean onePermissionGranted = false;
        for (NamedPermission permissionConstant : securityCheckData.getPermissionValues()) {
            String beanName = nameFactory.generatePermissionBeanName(permissionConstant.name());

            GenericPermissionVoter voter = CDIUtils.retrieveInstanceByName(beanName, GenericPermissionVoter.class);
            Set<SecurityViolation> violations = voter.checkPermission(context);
            if (violations.isEmpty()) {
                onePermissionGranted = true;
            }
            result.addAll(violations);

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
        return SecurityCheckType.NAMED_PERMISSION;
    }
}
