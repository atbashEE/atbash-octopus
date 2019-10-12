/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
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

import be.atbash.ee.security.octopus.authz.annotation.RequiresPermissions;
import be.atbash.ee.security.octopus.authz.checks.AnnotationAuthorizationChecker;
import be.atbash.ee.security.octopus.authz.testclasses.ClassCheck;
import be.atbash.ee.security.octopus.authz.testclasses.MethodCheck;
import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.OctopusRestConfiguration;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.TestReflectionUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.ws.rs.container.ResourceInfo;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class OctopusAnnotationContainerRequestFilterTest {

    @Mock
    private OctopusCoreConfiguration configMock;

    @Mock
    private OctopusRestConfiguration restConfigurationMock;

    @Mock
    private AnnotationAuthorizationChecker annotationAuthorizationCheckerMock;

    @Mock
    private SecurityViolationInfoProducer infoProducerMock;

    @Mock
    private ResourceInfo resourceInfoMock;

    private OctopusAnnotationContainerRequestFilter filter;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() throws NoSuchFieldException {
        filter = new OctopusAnnotationContainerRequestFilter();

        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(configMock, OctopusCoreConfiguration.class);
        beanManagerFake.registerBean(restConfigurationMock, OctopusRestConfiguration.class);
        beanManagerFake.registerBean(annotationAuthorizationCheckerMock, AnnotationAuthorizationChecker.class);
        beanManagerFake.registerBean(infoProducerMock, SecurityViolationInfoProducer.class);

        beanManagerFake.endRegistration();

        TestReflectionUtils.setFieldValue(filter, "resourceInfo", resourceInfoMock);
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void filter_method_allowed() throws IOException, NoSuchMethodException {
        Class methodCheckClass = MethodCheck.class;
        when(resourceInfoMock.getResourceClass()).thenReturn(methodCheckClass);
        Method method = MethodCheck.class.getMethod("doSomething");

        when(resourceInfoMock.getResourceMethod()).thenReturn(method);

        when(restConfigurationMock.isRestInterceptorEnabled()).thenReturn(true);

        DummyAnswerMethod answer = new DummyAnswerMethod(false, "testMethod");
        when(annotationAuthorizationCheckerMock.checkAccess(anySet(), any(AccessDecisionVoterContext.class))).then(answer);

        filter.filter(null);

        verify(annotationAuthorizationCheckerMock).checkAccess(anySet(), any(AccessDecisionVoterContext.class));
    }

    @Test(expected = UnauthorizedException.class)
    public void filter_method_notAllowed() throws IOException, NoSuchMethodException {
        Class methodCheckClass = MethodCheck.class;
        when(resourceInfoMock.getResourceClass()).thenReturn(methodCheckClass);
        Method method = MethodCheck.class.getMethod("doSomething");

        when(resourceInfoMock.getResourceMethod()).thenReturn(method);

        when(restConfigurationMock.isRestInterceptorEnabled()).thenReturn(true);

        DummyAnswerMethod answer = new DummyAnswerMethod(true, "testMethod");
        when(annotationAuthorizationCheckerMock.checkAccess(anySet(), any(AccessDecisionVoterContext.class))).then(answer);

        try {
            filter.filter(null);
        } finally {

            verify(annotationAuthorizationCheckerMock).checkAccess(anySet(), any(AccessDecisionVoterContext.class));
        }
    }

    @Test
    public void filter_class_allowed() throws IOException, NoSuchMethodException {
        Class classCheckClass = ClassCheck.class;
        when(resourceInfoMock.getResourceClass()).thenReturn(classCheckClass);
        Method method = ClassCheck.class.getMethod("doSomething");

        when(resourceInfoMock.getResourceMethod()).thenReturn(method);

        when(restConfigurationMock.isRestInterceptorEnabled()).thenReturn(true);

        DummyAnswerClass answer = new DummyAnswerClass(false, "testMethod");
        when(annotationAuthorizationCheckerMock.checkAccess(anySet(), any(AccessDecisionVoterContext.class))).then(answer);

        filter.filter(null);

        verify(annotationAuthorizationCheckerMock, times(2)).checkAccess(anySet(), any(AccessDecisionVoterContext.class));
    }

    @Test(expected = UnauthorizedException.class)
    public void filter_class_notallowed() throws IOException, NoSuchMethodException {
        Class classCheckClass = ClassCheck.class;
        when(resourceInfoMock.getResourceClass()).thenReturn(classCheckClass);
        Method method = ClassCheck.class.getMethod("doSomething");

        when(resourceInfoMock.getResourceMethod()).thenReturn(method);

        when(restConfigurationMock.isRestInterceptorEnabled()).thenReturn(true);

        DummyAnswerClass answer = new DummyAnswerClass(true, "testMethod");
        when(annotationAuthorizationCheckerMock.checkAccess(anySet(), any(AccessDecisionVoterContext.class))).then(answer);

        try {
            filter.filter(null);
        } finally {

            verify(annotationAuthorizationCheckerMock, times(2)).checkAccess(anySet(), any(AccessDecisionVoterContext.class));
        }
    }

    @Test
    public void filter_notActive() throws IOException, NoSuchMethodException {
        Class methodCheckClass = MethodCheck.class;
        when(resourceInfoMock.getResourceClass()).thenReturn(methodCheckClass);
        Method method = MethodCheck.class.getMethod("doSomething");

        when(resourceInfoMock.getResourceMethod()).thenReturn(method);

        when(restConfigurationMock.isRestInterceptorEnabled()).thenReturn(false);

        filter.filter(null);

        verify(annotationAuthorizationCheckerMock, never()).checkAccess(anySet(), any(AccessDecisionVoterContext.class));
    }

    @Test(expected = SecurityAuthorizationViolationException.class)
    public void filter_noAnnotation() throws IOException, NoSuchMethodException {
        // The test class / method has correct annotation but with annotationAuthorizationCheckerMock.checkAccess always returns false
        // for this test as if there are no annotations
        Class methodCheckClass = MethodCheck.class;
        when(resourceInfoMock.getResourceClass()).thenReturn(methodCheckClass);
        Method method = MethodCheck.class.getMethod("doSomething");

        when(resourceInfoMock.getResourceMethod()).thenReturn(method);

        when(restConfigurationMock.isRestInterceptorEnabled()).thenReturn(true);

        when(annotationAuthorizationCheckerMock.checkAccess(anySet(), any(AccessDecisionVoterContext.class))).thenReturn(false);

        try {
            filter.filter(null);
        } finally {

            verify(annotationAuthorizationCheckerMock, times(2)).checkAccess(anySet(), any(AccessDecisionVoterContext.class));
        }
    }

    private static class DummyAnswerMethod implements Answer<Boolean> {

        private boolean exception;
        private String expectedPermission;

        public DummyAnswerMethod(boolean exception, String expectedPermission) {
            this.exception = exception;
            this.expectedPermission = expectedPermission;
        }

        @Override
        public Boolean answer(InvocationOnMock invocationOnMock) throws Throwable {
            Set<Annotation> annotations = invocationOnMock.getArgument(0);
            if (annotations.size() == 1) {
                Annotation annotation = annotations.iterator().next();
                if (annotation.annotationType().equals(RequiresPermissions.class)) {
                    if (!((RequiresPermissions) annotation).value()[0].equals(expectedPermission)) {

                        throw new IllegalArgumentException("Expect RequiresPermission with " + expectedPermission);
                    }
                } else {
                    throw new IllegalArgumentException("Only expect RequiresPermission annotation");

                }
            } else {
                throw new IllegalArgumentException("Only expect 1 RequiresPermission annotation");
            }


            if (exception) {
                throw new UnauthorizedException();
            }
            return true;
        }
    }

    private static class DummyAnswerClass implements Answer<Boolean> {

        private boolean exception;
        private String expectedPermission;

        public DummyAnswerClass(boolean exception, String expectedPermission) {
            this.exception = exception;
            this.expectedPermission = expectedPermission;
        }

        @Override
        public Boolean answer(InvocationOnMock invocationOnMock) throws Throwable {
            Set<Annotation> annotations = invocationOnMock.getArgument(0);
            if (annotations.size() == 1) {
                Annotation annotation = annotations.iterator().next();
                if (annotation.annotationType().equals(RequiresPermissions.class)) {
                    if (!((RequiresPermissions) annotation).value()[0].equals(expectedPermission)) {

                        throw new IllegalArgumentException("Expect RequiresPermission with " + expectedPermission);
                    }
                } else {
                    throw new IllegalArgumentException("Only expect RequiresPermission annotation");

                }
            } else {
                return false;
            }


            if (exception) {
                throw new UnauthorizedException();
            }
            return true;
        }
    }
}