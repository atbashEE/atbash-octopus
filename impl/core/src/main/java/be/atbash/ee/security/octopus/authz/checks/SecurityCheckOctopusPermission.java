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
import be.atbash.ee.security.octopus.authz.annotation.RequiresPermissions;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.StringPermissionLookup;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationUtil;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.interceptor.InvocationContext;
import java.lang.annotation.Annotation;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * SecurityCheck for the annotation @OctopusPermissions which takes String permission (named, wildcard or short version)
 */
@ApplicationScoped
public class SecurityCheckOctopusPermission implements SecurityCheck {
    // FIXME Duplicate, remove
    @Inject
    private SecurityViolationInfoProducer infoProducer;

    private StringPermissionLookup stringPermissionLookup;

    private Map<String, NamedDomainPermission> permissionCache;

    @PostConstruct
    public void init() {
        // StringPermissionProvider is optional, created by a Producer.
        // FIXME Verify if this is now covered (There was in previous version a specific handling for producers of optional instances.
        stringPermissionLookup = CDIUtils.retrieveOptionalInstance(StringPermissionLookup.class);

        permissionCache = new HashMap<>();
    }

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;

        if (!subject.isAuthenticated() && !subject.isRemembered()) {  // When login from remember me, the isAuthenticated return false
            result = SecurityCheckInfo.withException(
                    new SecurityViolationException("User required", infoProducer.getViolationInfo(accessContext))
            );
        } else {
            Set<SecurityViolation> securityViolations = performPermissionChecks(securityAnnotation, subject, accessContext);
            if (!securityViolations.isEmpty()) {
                result = SecurityCheckInfo.withException(
                        new SecurityViolationException(securityViolations));
            } else {
                result = SecurityCheckInfo.allowAccess();
            }
        }

        return result;
    }

    private Set<SecurityViolation> performPermissionChecks(Annotation octopusPermission, Subject subject, AccessDecisionVoterContext accessContext) {
        Set<SecurityViolation> result = new HashSet<>();

        Combined permissionCombination = AnnotationUtil.getPermissionCombination(octopusPermission);
        boolean onePermissionGranted = false;
        NamedDomainPermission permission;
        for (String permissionString : AnnotationUtil.getStringValues(octopusPermission)) {
            if (stringPermissionLookup != null) {
                permission = stringPermissionLookup.getPermission(permissionString);
                // TODO What if we specify a String value which isn't defined in the lookup?
            } else {
                permission = permissionCache.get(permissionString);
                if (permission == null) {
                    if (!permissionString.contains(":")) {
                        permissionString += ":*:*";
                    }
                    permission = new NamedDomainPermission(StringPermissionLookup.createNameForPermission(permissionString), permissionString);
                    permissionCache.put(permissionString, permission);
                }

            }

            if (subject.isPermitted(permission)) {
                onePermissionGranted = true;
            } else {
                InvocationContext invocationContext = accessContext.getSource();
                result.add(infoProducer.defineViolation(invocationContext, permission));
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
    public boolean hasSupportFor(Object annotation) {
        return RequiresPermissions.class.isAssignableFrom(annotation.getClass());
    }
}
