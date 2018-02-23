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
package be.atbash.ee.security.octopus.util;

import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.util.PublicAPI;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.interceptor.InvocationContext;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@ApplicationScoped
@PublicAPI
public class MethodParameterCheckUtil {

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    public SecurityViolation checkMethodHasParameterTypes(final InvocationContext invocationContext, Class<?>... parameterTypes) {
        final List<Class<?>> missingClasses = new ArrayList<>();
        for (Class<?> type : parameterTypes) {
            if (!hasAssignableParameter(invocationContext.getParameters(), type)) {
                missingClasses.add(type);
            }
        }
        SecurityViolation result = null;
        if (!missingClasses.isEmpty()) {
            result = new SecurityViolation() {
                @Override
                public String getReason() {
                    return infoProducer.getWrongMethodSignatureInfo(invocationContext, missingClasses);
                }
            };
        }
        return result;
    }

    private boolean hasAssignableParameter(Object[] parameters, Class<?> type) {
        boolean result = false;
        int idx = 0;
        boolean nullValueFound = false;
        while (!result && idx < parameters.length) {
            if (parameters[idx] == null) {
                nullValueFound = true;
            } else {
                result = type.isAssignableFrom(parameters[idx].getClass());
            }
            idx++;
        }
        return result || nullValueFound;
    }

    public <T> T getAssignableParameter(InvocationContext invocationContext, Class<T> type) {
        return getAssignableParameter(invocationContext, type, 0);
    }

    public <T> T getAssignableParameter(InvocationContext invocationContext, Class<T> type, int pos) {
        int idx = 0;
        int found = -1;
        Object[] parameters = invocationContext.getParameters();
        T result = null;
        while (result == null && idx < parameters.length) {
            if (parameters[idx] != null && type.isAssignableFrom(parameters[idx].getClass())) {
                found++;
                if (found == pos) {
                    result = (T) parameters[idx];
                }
            }
            idx++;
        }
        return result;
    }
}
