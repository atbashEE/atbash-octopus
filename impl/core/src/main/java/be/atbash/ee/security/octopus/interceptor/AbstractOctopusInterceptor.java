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
import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationInfo;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;

import javax.inject.Inject;
import java.lang.annotation.Annotation;
import java.util.Set;

/**
 *
 */

public abstract class AbstractOctopusInterceptor {

    @Inject
    protected SecurityViolationInfoProducer infoProducer;

    @Inject
    protected AnnotationAuthorizationChecker annotationAuthorizationChecker;

    /**
     * Only call from an environment where no CDI is available.
     */
    protected final void init() {
        annotationAuthorizationChecker = new AnnotationAuthorizationChecker();
    }

    protected void checkAuthorization(AccessDecisionVoterContext accessContext, AnnotationInfo info) {

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
