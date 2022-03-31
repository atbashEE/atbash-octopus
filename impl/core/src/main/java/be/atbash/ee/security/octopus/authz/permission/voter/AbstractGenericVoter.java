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
package be.atbash.ee.security.octopus.authz.permission.voter;

import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.util.MethodParameterCheckUtil;
import be.atbash.util.PublicAPI;
import org.apache.deltaspike.security.api.authorization.AbstractAccessDecisionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import jakarta.inject.Inject;
import java.util.Set;

/**
 * Base class for creating custom voters.
 * TODO JavaDoc
 */
@PublicAPI
public abstract class AbstractGenericVoter extends AbstractAccessDecisionVoter {

    @Inject
    protected MethodParameterCheckUtil methodParameterCheckUtil;

    @Inject
    protected SecurityViolationInfoProducer infoProducer;

    @Inject
    protected UserPrincipal userPrincipal;

    @Inject
    protected Subject subject;

    protected void checkMethodHasParameterTypes(Set<SecurityViolation> violations, OctopusInvocationContext invocationContext, Class<?>... parameterTypes) {
        SecurityViolation violation = methodParameterCheckUtil.checkMethodHasParameterTypes(invocationContext, parameterTypes);
        if (violation != null) {
            violations.add(violation);
        }
    }

    protected boolean verifyMethodHasParameterTypes(OctopusInvocationContext invocationContext, Class<?>... parameterTypes) {
        SecurityViolation violation = methodParameterCheckUtil.checkMethodHasParameterTypes(invocationContext, parameterTypes);
        return violation == null;
    }

    /*
    FIXME Move to a AbstractWebGenericVoter
    protected boolean hasServletRequestInfo(OctopusInvocationContext invocationContext) {
        SecurityViolation violation = methodParameterCheckUtil.checkMethodHasParameterTypes(invocationContext, HttpServletRequest.class);
        return violation == null;
    }

    protected String getURLRequestParameter(OctopusInvocationContext invocationContext, String paramName) {
        HttpServletRequest httpServletRequest = methodParameterCheckUtil.getAssignableParameter(invocationContext, HttpServletRequest.class);
        return httpServletRequest.getParameter(paramName);
    }

     */

    public boolean verify(AccessDecisionVoterContext invocationContext) {
        return checkPermission(invocationContext).isEmpty();
    }
}
