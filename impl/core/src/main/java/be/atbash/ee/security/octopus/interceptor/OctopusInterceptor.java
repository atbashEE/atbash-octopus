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
package be.atbash.ee.security.octopus.interceptor;

import be.atbash.ee.security.octopus.authz.checks.AnnotationAuthorizationChecker;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationInfo;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationUtil;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;

import jakarta.inject.Inject;
import jakarta.interceptor.AroundInvoke;
import jakarta.interceptor.Interceptor;
import jakarta.interceptor.InvocationContext;
import java.io.Serializable;
import java.lang.reflect.Method;

@Interceptor
@OctopusInterceptorBinding
public class OctopusInterceptor extends AbstractOctopusInterceptor implements Serializable {

    private static final long serialVersionUID = 1L;

    @Inject
    private OctopusCoreConfiguration config;

    //@PostConstruct With Weld 2.X, there seems to be an issue
    public void init(InvocationContext context) {
        if (config == null) {
            // WLS12C doesn't inject into interceptors
            config = CDIUtils.retrieveInstance(OctopusCoreConfiguration.class);
            infoProducer = CDIUtils.retrieveInstance(SecurityViolationInfoProducer.class);
            annotationAuthorizationChecker = CDIUtils.retrieveInstance(AnnotationAuthorizationChecker.class);
        }
    }

    @AroundInvoke
    public Object interceptForSecurity(InvocationContext context) throws Exception {
        init(context);  // Since @PostConstruct isn't allowed in Weld 2.x

        Class<?> classType = context.getTarget().getClass();
        Method method = context.getMethod();

        AnnotationInfo info = AnnotationUtil.getAllAnnotations(config, classType, method);

        OctopusInvocationContext invocationContext = new OctopusInvocationContext(context);
        invocationContext.addContextData(AnnotationInfo.class.getName(), info);
        AccessDecisionVoterContext accessContext = new CustomAccessDecisionVoterContext(invocationContext);

        checkAuthorization(accessContext, info);
        return context.proceed();
    }

}
