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

import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.ee.security.octopus.interceptor.AbstractOctopusInterceptor;
import be.atbash.ee.security.octopus.interceptor.CustomAccessDecisionVoterContext;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationInfo;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationUtil;
import be.atbash.util.reflection.ClassUtils;

import java.lang.reflect.Method;

/**
 *
 */

public class MethodAuthorizationChecker extends AbstractOctopusInterceptor {

    private static final OctopusCoreConfiguration octopusCoreConfiguration = OctopusCoreConfiguration.getInstance();

    public MethodAuthorizationChecker() {
        init();
    }

    public static void checkAuthorization() {
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        Method method = methodFor(stackTrace[2]);
        new MethodAuthorizationChecker().checkAuthorization(method);
    }

    private void checkAuthorization(Method method) {
        AnnotationInfo info = AnnotationUtil.getAllAnnotations(octopusCoreConfiguration, method.getDeclaringClass(), method);
        OctopusInvocationContext context = new OctopusInvocationContext(method.getDeclaringClass(), method, null);
        CustomAccessDecisionVoterContext accessDecissionVoterContext = new CustomAccessDecisionVoterContext(context);

        checkAuthorization(accessDecissionVoterContext, info);
    }

    private static Method methodFor(StackTraceElement stackTraceElement) {
        Class<?> aClass = ClassUtils.forName(stackTraceElement.getClassName());
        return findMethod(aClass, stackTraceElement.getMethodName());

    }

    private static Method findMethod(Class<?> aClass, String methodName) {
        Method result = null;
        for (Method method : aClass.getDeclaredMethods()) {
            if (methodName.equals(method.getName())) {
                result = method;
            }
        }
        return result;
    }
}
