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
package be.atbash.ee.security.octopus.authz;

import be.atbash.ee.security.octopus.authz.checks.AnnotationAuthorizationChecker;
import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.OctopusRestConfiguration;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.ee.security.octopus.interceptor.CustomAccessDecisionVoterContext;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationInfo;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationUtil;
import be.atbash.util.CDIUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ResourceInfo;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Set;

/**
 *
 */
@Provider
public class OctopusAnnotationContainerRequestFilter implements ContainerRequestFilter {

    @Context
    private ResourceInfo resourceInfo;

    // We cannot use Inject as this is not working on all servers
    private OctopusCoreConfiguration config;

    private OctopusRestConfiguration restConfiguration;

    private AnnotationAuthorizationChecker annotationAuthorizationChecker;

    private SecurityViolationInfoProducer infoProducer;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        checkDependencies();
        Class<?> classType = resourceInfo.getResourceClass();
        Method method = resourceInfo.getResourceMethod();

        // TODO Is the OctopusInvocationContext a good idea here?
        OctopusInvocationContext context = new OctopusInvocationContext(method, null);
        AccessDecisionVoterContext accessContext = new CustomAccessDecisionVoterContext(context);

        AnnotationInfo info = AnnotationUtil.getAllAnnotations(config, classType, method);

        // Developer can indicate that the Authorization checks shouldn't happen here :
        // - JAX-RS endpoint is defined as an EJB
        // - Endpoint is used by other application which is not Octopus based and thus we don't have the authorization enforcements

        if (restConfiguration.isRestInterceptorEnabled()) {

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
                throw new SecurityAuthorizationViolationException("No Authorization requirements available", infoProducer.getViolationInfo(accessContext));

            }
        }

    }

    private void checkDependencies() {
        if (config == null) {
            config = CDIUtils.retrieveInstance(OctopusCoreConfiguration.class);
            restConfiguration = CDIUtils.retrieveInstance(OctopusRestConfiguration.class);
            annotationAuthorizationChecker = CDIUtils.retrieveInstance(AnnotationAuthorizationChecker.class);
            infoProducer = CDIUtils.retrieveInstance(SecurityViolationInfoProducer.class);
        }
    }
}
