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

import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.security.api.authorization.AbstractAccessDecisionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.HashSet;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
public class SecurityCheckCustomVoterCheck implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;  // FIXME Why is this not used

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, SecurityCheckData securityCheckData) {
        SecurityCheckInfo result;

        Set<SecurityViolation> securityViolations = performCustomChecks(securityCheckData, accessContext);
        if (!securityViolations.isEmpty()) {

            result = SecurityCheckInfo.withException(
                    new SecurityAuthorizationViolationException(securityViolations)
            );
        } else {
            result = SecurityCheckInfo.allowAccess();
        }

        return result;
    }

    private Set<SecurityViolation> performCustomChecks(SecurityCheckData securityCheckData, AccessDecisionVoterContext context) {
        Set<SecurityViolation> result = new HashSet<>();
        for (Class<?> clsName : securityCheckData.getClassValues()) {
            // We are sure that this are all AbstractAccessDecisionVoter classes since they come from be.atbash.ee.security.octopus.authz.annotation.CustomVoterCheck.value
            AbstractAccessDecisionVoter voter = (AbstractAccessDecisionVoter) CDIUtils.retrieveInstance(clsName);
            result.addAll(voter.checkPermission(context));
        }

        return result;
    }

    @Override
    public SecurityCheckType getSecurityCheckType() {
        return SecurityCheckType.CUSTOM_VOTER;
    }
}
