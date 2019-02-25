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
package be.atbash.ee.security.octopus.authz.checks;

import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.systemaccount.internal.SystemAccountPrincipal;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.util.Arrays;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class SecurityCheckSystemAccountCheck implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, SecurityCheckData securityCheckData) {
        SecurityCheckInfo result;

        List<String> identifiers = Arrays.asList(securityCheckData.getValues());

        Object principal = subject.getPrincipal();
        if (principal instanceof SystemAccountPrincipal) {

            if (subject.isAuthenticated()) {
                SystemAccountPrincipal systemAccountPrincipal = (SystemAccountPrincipal) principal;
                if (identifiers.contains(systemAccountPrincipal.getIdentifier())) {
                    result = SecurityCheckInfo.allowAccess();
                } else {
                    result = SecurityCheckInfo.withException(new SecurityAuthorizationViolationException("System account '" + systemAccountPrincipal.getIdentifier() + "' not allowed",
                            infoProducer.getViolationInfo(accessContext)));
                }
            } else {
                result = SecurityCheckInfo.withException(new SecurityAuthorizationViolationException("Authenticated System account required", infoProducer.getViolationInfo(accessContext)));
            }
        } else {
            result = SecurityCheckInfo.withException(new SecurityAuthorizationViolationException("System account required", infoProducer.getViolationInfo(accessContext)));
        }
        return result;
    }

    @Override
    public SecurityCheckType getSecurityCheckType() {
        return SecurityCheckType.SYSTEM_ACCOUNT;
    }
}
