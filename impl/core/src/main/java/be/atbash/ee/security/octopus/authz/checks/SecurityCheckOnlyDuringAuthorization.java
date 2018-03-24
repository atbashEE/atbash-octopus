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
import be.atbash.ee.security.octopus.util.onlyduring.TemporaryAuthorizationContextManager;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class SecurityCheckOnlyDuringAuthorization implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, SecurityCheckData securityCheckData) {
        SecurityCheckInfo result;
        // No longer perform the check on subject.getPrincipal() in case we wan't to log on when another user is already logged on (and no logout is done)
        if (!TemporaryAuthorizationContextManager.isInAuthorization()) {
            result = SecurityCheckInfo.withException(
                    new SecurityAuthorizationViolationException("Execution of method only allowed during authorization process"
                            , infoProducer.getViolationInfo(accessContext)));
        } else {
            result = SecurityCheckInfo.allowAccess();
        }

        return result;
    }

    @Override
    public SecurityCheckType getSecurityCheckType() {
        return SecurityCheckType.ONLY_DURING_AUTHORIZATION;
    }
}
