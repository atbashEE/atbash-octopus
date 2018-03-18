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

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authz.UnauthorizedException;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationUtil;
import be.atbash.ee.security.octopus.subject.Subject;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;

import javax.annotation.security.PermitAll;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.lang.annotation.Annotation;
import java.util.Iterator;
import java.util.Set;

/**
 *
 */
@ApplicationScoped
public class AnnotationAuthorizationChecker {

    private static final Object LOCK = new Object();

    @Inject
    private AnnotationCheckFactory annotationCheckFactory;

    public boolean checkAccess(Set<Annotation> annotations, AccessDecisionVoterContext accessContext) {
        checkDependencies();
        UnauthorizedException exception = null;
        boolean accessAllowed = false;

        if (!annotations.isEmpty()) {
            if (AnnotationUtil.hasAnnotation(annotations, PermitAll.class)) {
                accessAllowed = true;
            } else {
                Subject subject = SecurityUtils.getSubject();
                Iterator<Annotation> annotationIterator = annotations.iterator();

                while (!accessAllowed && annotationIterator.hasNext()) {
                    Annotation annotation = annotationIterator.next();
                    SecurityCheckInfo checkInfo = annotationCheckFactory.getCheck(annotation).performCheck(subject, accessContext, annotation);
                    if (checkInfo.isAccessAllowed()) {
                        accessAllowed = true;
                    }
                    if (checkInfo.getException() != null) {
                        exception = checkInfo.getException();
                    }

                }
            }
            if (!accessAllowed && exception != null) {
                throw exception;
            }
        }

        return accessAllowed;
    }

    private void checkDependencies() {
        // Needed for the Java SE usage.
        if (annotationCheckFactory == null) {
            synchronized (LOCK) {
                if (annotationCheckFactory == null) {
                    annotationCheckFactory = new AnnotationCheckFactory();
                    annotationCheckFactory.initChecks();
                }
            }
        }
    }

}
