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
package be.atbash.ee.security.octopus.interceptor.annotation;

import be.atbash.util.PublicAPI;

import java.lang.annotation.Annotation;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 *
 */
@PublicAPI
public class AnnotationInfo {

    private Set<Annotation> methodAnnotations = new HashSet<>();
    private Set<Annotation> classAnnotations = new HashSet<>();

    public void addMethodAnnotation(Annotation annotation) {
        methodAnnotations.add(annotation);
    }

    public void addClassAnnotation(Annotation annotation) {
        classAnnotations.add(annotation);
    }

    public Set<Annotation> getMethodAnnotations() {
        methodAnnotations.remove(null);
        return methodAnnotations;
    }

    public Set<Annotation> getClassAnnotations() {
        classAnnotations.remove(null);
        return classAnnotations;
    }

    public List<Annotation> getAnnotation(Class<? extends Annotation> annotationClass) {
        List<Annotation> result = new ArrayList<>();
        for (Annotation methodAnnotation : methodAnnotations) {
            if (methodAnnotation != null && annotationClass.isAssignableFrom(methodAnnotation.getClass())) {
                result.add(methodAnnotation);
            }
        }

        for (Annotation classAnnotation : classAnnotations) {
            if (classAnnotation != null && annotationClass.isAssignableFrom(classAnnotation.getClass())) {
                result.add(classAnnotation);
            }
        }

        return result;
    }
}
