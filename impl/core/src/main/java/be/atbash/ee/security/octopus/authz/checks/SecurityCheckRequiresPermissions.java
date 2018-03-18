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

import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.annotation.RequiresPermissions;
import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.subject.Subject;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.lang.annotation.Annotation;

/**
 *
 */
@ApplicationScoped
public class SecurityCheckRequiresPermissions implements SecurityCheck {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    public void initDependencies() {
        infoProducer = new SecurityViolationInfoProducer();
    }

    @Override
    public SecurityCheckInfo performCheck(Subject subject, AccessDecisionVoterContext accessContext, Annotation securityAnnotation) {
        SecurityCheckInfo result;

        RequiresPermissions requiresPermissions = (RequiresPermissions) securityAnnotation;
        String[] permissions = requiresPermissions.value();
        try {
            subject.checkPermissions(permissions);
            result = SecurityCheckInfo.allowAccess();
        } catch (AuthorizationException ae) {
            result = SecurityCheckInfo.withException(
                    new SecurityAuthorizationViolationException("User has not required Permission", infoProducer.getViolationInfo(accessContext))
            );
        }
        return result;
    }

    @Override
    public boolean hasSupportFor(Object annotation) {
        return RequiresPermissions.class.isAssignableFrom(annotation.getClass());
    }
}
