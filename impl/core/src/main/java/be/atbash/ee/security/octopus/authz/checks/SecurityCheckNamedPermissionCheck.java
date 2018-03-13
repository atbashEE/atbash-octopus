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
package be.atbash.ee.security.octopus.authz.checks;

import be.atbash.ee.security.octopus.authz.Combined;
import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.voter.GenericPermissionVoter;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.names.VoterNameFactory;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationUtil;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.lang.annotation.Annotation;
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
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;

        if (!subject.isAuthenticated() && !subject.isRemembered()) {  // When login from remember me, the isAuthenticated return false
            result = SecurityCheckInfo.withException(
                    new SecurityViolationException("User required", infoProducer.getViolationInfo(accessContext))
            );
        } else {
            Set<SecurityViolation> securityViolations = performNamedPermissionChecks(securityAnnotation, accessContext);
            if (!securityViolations.isEmpty()) {
                result = SecurityCheckInfo.withException(
                        new SecurityViolationException(securityViolations));
            } else {
                result = SecurityCheckInfo.allowAccess();
            }
        }

        return result;
    }

    private Set<SecurityViolation> performNamedPermissionChecks(Annotation customNamedCheck, AccessDecisionVoterContext context) {
        Set<SecurityViolation> result = new HashSet<>();

        Combined permissionCombination = AnnotationUtil.getPermissionCombination(customNamedCheck);
        boolean onePermissionGranted = false;
        for (Object permissionConstant : AnnotationUtil.getPermissionValues(customNamedCheck)) {
            String beanName = nameFactory.generatePermissionBeanName(((NamedPermission) permissionConstant).name());

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
    public boolean hasSupportFor(Object annotation) {
        return config.getNamedPermissionCheckClass() != null && config.getNamedPermissionCheckClass().isAssignableFrom(annotation.getClass());
    }
}
