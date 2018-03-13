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

import org.apache.deltaspike.core.api.literal.DefaultLiteral;
import org.apache.deltaspike.core.api.literal.DependentScopeLiteral;
import org.apache.deltaspike.core.api.literal.SpecializesLiteral;
import org.junit.Before;
import org.junit.Test;

import java.lang.annotation.Annotation;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class AnnotationInfoTest {

    private AnnotationInfo info;

    @Before
    public void setup() {
        info = new AnnotationInfo();

        info.addMethodAnnotation(new DefaultLiteral());
        info.addClassAnnotation(new SpecializesLiteral());
    }

    @Test
    public void getAnnotation_MethodAnnotation() {
        List<Annotation> annotations = info.getAnnotation(DefaultLiteral.class);
        assertThat(annotations).hasSize(1);
        assertThat(annotations).containsExactly(new DefaultLiteral());
    }

    @Test
    public void getAnnotation_ClassAnnotation() {
        List<Annotation> annotations = info.getAnnotation(SpecializesLiteral.class);
        assertThat(annotations).hasSize(1);
        assertThat(annotations).containsExactly(new SpecializesLiteral());
    }

    @Test
    public void getAnnotation_NotFound() {
        List<Annotation> annotations = info.getAnnotation(DependentScopeLiteral.class);
        assertThat(annotations).isEmpty();
    }

}