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
package be.atbash.ee.security.octopus.authz.violation;

import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.util.PublicAPI;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import javax.enterprise.context.ApplicationScoped;
import javax.interceptor.InvocationContext;
import java.util.Arrays;
import java.util.List;

/**
 * TODO JavaDoc
 */
@ApplicationScoped
@PublicAPI
public class SecurityViolationInfoProducer {

    public String getViolationInfo(AccessDecisionVoterContext accessContext) {
        InvocationContext context = accessContext.getSource();
        return getExceptionPointInfo(context);
    }

    public String getViolationInfo(AccessDecisionVoterContext accessContext, SecurityViolation securityViolation) {
        AuthorizationViolation violation = defineCustomViolation(accessContext, securityViolation);
        if (violation == null) {
            InvocationContext context = accessContext.getSource();
            violation = new BasicAuthorizationViolation(securityViolation.getReason(), getExceptionPointInfo(context));
        }
        return violation.toString();
    }

    public String getViolationInfo(AccessDecisionVoterContext accessDecisionVoterContext, Permission violatedPermission) {
        AuthorizationViolation violation = defineCustomViolation(accessDecisionVoterContext, violatedPermission);
        if (violation == null) {
            InvocationContext invocationContext = accessDecisionVoterContext.getSource();
            violation = defineViolation(invocationContext, violatedPermission);
        }
        return violation.toString();
    }

    public AuthorizationViolation defineViolation(InvocationContext invocationContext, Permission violatedPermission) {
        String permissionInfo = null;
        if (violatedPermission instanceof NamedDomainPermission) {
            NamedDomainPermission namedPermission = (NamedDomainPermission) violatedPermission;
            permissionInfo = "Permission " + namedPermission.getName();
        }
        if (violatedPermission instanceof RolePermission) {
            RolePermission namedRole = (RolePermission) violatedPermission;
            permissionInfo = "Role " + namedRole.getRoleName();
        }
        return new BasicAuthorizationViolation(permissionInfo, getExceptionPointInfo(invocationContext));
    }

    protected AuthorizationViolation defineCustomViolation(AccessDecisionVoterContext accessDecisionVoterContext, Permission violatedPermission) {
        return null; // TODO Find out what the intention was. This doesn't seems very usefull
    }

    protected AuthorizationViolation defineCustomViolation(AccessDecisionVoterContext accessDecisionVoterContext, SecurityViolation violation) {
        return null; // TODO Find out what the intention was. This doesn't seems very usefull
    }

    protected String getExceptionPointInfo(InvocationContext invocationContext) {
        // FIXME This is specific for JSF or other HTML based view since it contains <br/>
        StringBuilder result = new StringBuilder();
        if (!(invocationContext instanceof OctopusInvocationContext)) {
            result.append("Class ").append(invocationContext.getTarget().getClass().getName());
            result.append("<br/>Method ").append(invocationContext.getMethod().getName());
            result.append("<br/>Parameters ");
            if (invocationContext.getParameters() != null) {
                for (Object parameter : invocationContext.getParameters()) {
                    if (parameter == null) {
                        result.append("<br/>").append(" ? = null");
                    } else {
                        result.append("<br/>").append(parameter.getClass().getName()).append(" = ").append(parameter);
                    }
                }
            }
        }
        return result.toString();
    }

    public String getWrongMethodSignatureInfo(InvocationContext invocationContext, List<Class<?>> missingParameterTypes) {
        return new MethodParameterTypeViolation(getExceptionPointInfo(invocationContext), missingParameterTypes).toString();
    }

    public String getWrongOverloadingMethodSignatureInfo(InvocationContext invocationContext, Class<?>... missingParameterTypes) {
        return new OverloadingMethodParameterTypeViolation(getExceptionPointInfo(invocationContext), Arrays.asList(missingParameterTypes)).toString();
    }

}
