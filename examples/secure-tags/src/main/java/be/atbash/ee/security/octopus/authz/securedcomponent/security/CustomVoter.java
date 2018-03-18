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
package be.atbash.ee.security.octopus.authz.securedcomponent.security;

import be.atbash.ee.security.octopus.authz.annotation.RequiresPermissions;
import be.atbash.ee.security.octopus.authz.permission.voter.AbstractGenericVoter;
import be.atbash.ee.security.octopus.authz.permission.voter.GenericPermissionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.inject.Named;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
@Named
public class CustomVoter extends AbstractGenericVoter {

    @Inject
    @RequiresPermissions("demo:*:*")
    private GenericPermissionVoter demoPermissionVoter;

    @Inject
    @RequiresPermissions("nonExisting:*:*")
    //@RequiresPermissions()
    private GenericPermissionVoter nonExistingPermissionVoter;

    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {
        if (!"junit".equals(userPrincipal.getUserName())) {
            if (!demoPermissionVoter.verifyPermission()) {
                violations.add(newSecurityViolation("Custom rule verification failed : " + infoProducer.getViolationInfo(accessDecisionVoterContext)));
            }
        }
        if (nonExistingPermissionVoter.verifyPermission()) {
            violations.add(newSecurityViolation("Some with a non existing role" + infoProducer.getViolationInfo(accessDecisionVoterContext)));
        }
    }
}
