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
package be.atbash.ee.security.octopus.view.component.service;

import be.atbash.ee.security.octopus.authz.Combined;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.StringPermissionLookup;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.permission.role.voter.GenericRoleVoter;
import be.atbash.ee.security.octopus.authz.permission.voter.GenericPermissionVoter;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.ee.security.octopus.interceptor.CustomAccessDecisionVoterContext;
import be.atbash.ee.security.octopus.view.component.secured.SecuredComponentData;
import be.atbash.ee.security.octopus.view.component.secured.SecuredComponentDataParameter;
import be.atbash.util.CDIUtils;
import be.atbash.util.JsfUtils;
import org.apache.deltaspike.security.api.authorization.AbstractAccessDecisionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.slf4j.Logger;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.NoSuchElementException;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
public class ComponentAuthorizationService {

    @Inject
    private Logger logger;

    private StringPermissionLookup stringLookup;

    @PostConstruct
    public void init() {
        // StringPermissionLookup is Optional
        stringLookup = CDIUtils.retrieveOptionalInstance(StringPermissionLookup.class);
    }

    public boolean hasAccess(SecuredComponentData secureComponentData) {
        Combined combined = secureComponentData.getCombined();

        // initial value
        // AND : true -> When all voters allow access, it stays true and method return ACCESS ALLOWED
        // OR : false -> When all voters deny access, it stays false and method return ACCESS DISALLOWED
        boolean result = combined == Combined.AND;

        boolean partialResult;
        Object[] contextParameters = getContextParameters(secureComponentData);
        for (String voter : secureComponentData.getVoters()) {
            AbstractAccessDecisionVoter bean = getBean(voter.trim());

            if (bean == null) {
                // TODO Have we any trace that bean is not found?
                return false;
            }
            OctopusInvocationContext invocationContext = new OctopusInvocationContext(secureComponentData.getTargetComponent(), contextParameters);
            AccessDecisionVoterContext context = new CustomAccessDecisionVoterContext(invocationContext);

            Set<SecurityViolation> securityViolations = bean.checkPermission(context);

            // securityViolations empty -> access allowed
            partialResult = securityViolations.isEmpty();
            if (secureComponentData.isNot()) {
                // When not specified on tag -> invert result.
                partialResult = !partialResult;
            }
            // This then become the result.
            result = partialResult;
            if (combined == Combined.OR) {
                if (result) { // If we have OR and the voter allowed access -> global result allowed.
                    return true;
                }
            } else {
                if (!result) { // If we have AND and the voter does not allow access -> global result not allowed.
                    return false;
                }
            }
        }
        return result;
    }

    private Object[] getContextParameters(SecuredComponentData secureComponentData) {
        if (secureComponentData.getParameters() == null) {
            return new Object[0];
        }
        Object[] result = new Object[secureComponentData.getParameters().length];
        int idx = 0;
        for (SecuredComponentDataParameter parameter : secureComponentData.getParameters()) {
            if (parameter.isAtRuntime()) {
                result[idx++] = JsfUtils.evaluateExpression((String) parameter.getParameterData());
            } else {
                result[idx++] = parameter.getParameterData();
            }
        }
        return result;
    }

    private AbstractAccessDecisionVoter getBean(String name) {
        AbstractAccessDecisionVoter result = null;

        if (name.contains(":")) {
            if (name.startsWith("::")) {
                String realName = name.substring(2);
                result = GenericRoleVoter.createInstance(new RolePermission(realName));
            } else {
                NamedDomainPermission permission;
                if (name.startsWith(":")) {
                    // Remove the leading :
                    String realName = name.substring(1);
                    if (stringLookup == null) {
                        // We found a name but developer didn't specify some lookup. So assume :*:* at the end

                        permission = new NamedDomainPermission(StringPermissionLookup.createNameForPermission(realName), realName + ":*:*");
                    } else {
                        permission = stringLookup.getPermission(realName);
                    }
                } else {
                    // TODO During testing we found out that x:y fails, need to perform checks everywhere
                    // A full blown wildcard shiro permission
                    permission = new NamedDomainPermission(StringPermissionLookup.createNameForPermission(name), name);
                }
                // TODO Verify if permission can be null
                result = GenericPermissionVoter.createInstance(permission);
            }

        } else {
            try {
                result = CDIUtils.retrieveInstanceByName(name, AbstractAccessDecisionVoter.class);
            } catch (NoSuchElementException e) {
                logger.warn("The AccessDecisionVoter with name " + name + " is not found.");
            }
        }
        return result;
    }

}