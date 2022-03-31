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
package be.atbash.ee.security.octopus.interceptor.testclasses;

import be.atbash.ee.security.octopus.authz.permission.voter.AbstractGenericVoter;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import jakarta.enterprise.context.ApplicationScoped;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
public class TestCustomVoter extends AbstractGenericVoter {

    private boolean customAccess;

    @Override
    protected void checkPermission(AccessDecisionVoterContext accessDecisionVoterContext, Set<SecurityViolation> violations) {
        if (!customAccess) {
            SecurityViolationInfoProducer infoProducer = CDIUtils.retrieveInstance(SecurityViolationInfoProducer.class);
            violations.add(newSecurityViolation(infoProducer.getViolationInfo(accessDecisionVoterContext)));
        }
    }

    public void setCustomAccess(boolean customAccess) {
        this.customAccess = customAccess;
    }
}
