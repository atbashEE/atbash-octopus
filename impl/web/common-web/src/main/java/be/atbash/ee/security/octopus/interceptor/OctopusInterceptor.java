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
package be.atbash.ee.security.octopus.interceptor;

import be.atbash.ee.security.octopus.authz.checks.AnnotationAuthorizationChecker;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.context.internal.CustomAccessDecissionVoterContext;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationInfo;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationUtil;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;

import javax.ejb.Asynchronous;
import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;
import java.io.Serializable;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@Interceptor
@OctopusInterceptorBinding
public class OctopusInterceptor implements Serializable {

    private static final long serialVersionUID = 1L;

    @Inject
    private OctopusCoreConfiguration config;

    @Inject
    private SecurityViolationInfoProducer infoProducer;

    @Inject
    private AnnotationAuthorizationChecker annotationAuthorizationChecker;

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

        supportForAsynchronousEJB(context, method);

        AnnotationInfo info = AnnotationUtil.getAllAnnotations(config, classType, method);
        Map<String, Object> contextData = new HashMap<>();
        contextData.put(AnnotationInfo.class.getName(), info);
        InvocationContextWrapper wrapper = new InvocationContextWrapper(context, contextData);

        AccessDecisionVoterContext accessContext = new CustomAccessDecissionVoterContext(wrapper);

        // We need to check at 2 levels, method and then if not present at class level
        Set<Annotation> annotations = info.getMethodAnnotations();

        // This method can throw already a OctopusUnauthorizedException
        boolean accessAllowed = annotationAuthorizationChecker.checkAccess(annotations, accessContext);

        if (!accessAllowed) {
            // OK, at method level we didn't find any annotations.
            annotations = info.getClassAnnotations();

            // This method can throw already a OctopusUnauthorizedException
            accessAllowed = annotationAuthorizationChecker.checkAccess(annotations, accessContext);

        }
        if (!accessAllowed) {
            // Ok at classLevel also no info -> Exception
            throw new SecurityViolationException("No Authorization requirements available", infoProducer.getViolationInfo(accessContext));
        }
        return context.proceed();
    }

    private void supportForAsynchronousEJB(InvocationContext context, Method method) {
        Asynchronous asynchronous = method.getAnnotation(Asynchronous.class);
        if (asynchronous != null) {
            for (Object parameter : context.getParameters()) {

                throw new UnsupportedOperationException("FIXME Implement");
                /*
                if (parameter != null && OctopusSecurityContext.class.isAssignableFrom(parameter.getClass())) {
                    Subject subject = ((OctopusSecurityContext) parameter).getSubject();
                    ThreadContext.bind(subject);
                }
                */
            }
        }
    }

}
