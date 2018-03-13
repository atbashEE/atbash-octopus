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

import be.atbash.ee.security.octopus.authz.annotation.*;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.interceptor.testclasses.*;
import be.atbash.ee.security.octopus.systemaccount.SystemAccount;
import be.atbash.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.annotation.security.PermitAll;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */

@RunWith(MockitoJUnitRunner.class)
public class AnnotationUtilTest {

    @Mock
    private OctopusCoreConfiguration octopusConfigMock;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        // Define the Named permission check class
        when(octopusConfigMock.getNamedPermissionCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                return TestPermissionCheck.class;
            }
        });
        beanManagerFake = new BeanManagerFake();

    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void getAllAnnotations_ClassLevelCustomPermission() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new ClassLevelCustomPermission();
        Method method = target.getClass().getMethod("customPermission1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelCustomPermission.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(TestPermissionCheck.class);

        assertThat(((TestPermissionCheck) annotation).value()).containsOnly(TestPermission.PERMISSION1);
    }

    @Test
    public void getAllAnnotations_ClassLevelCustomVoter() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new ClassLevelCustomVoter();
        Method method = target.getClass().getMethod("customVoter1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelCustomVoter.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(CustomVoterCheck.class);

        assertThat(((CustomVoterCheck) annotation).value()).containsOnly(TestCustomVoter.class);
    }

    @Test
    public void getAllAnnotations_ClassLevelPermitAll() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new ClassLevelPermitAll();
        Method method = target.getClass().getMethod("permitAll1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelPermitAll.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(PermitAll.class);

    }

    @Test
    public void getAllAnnotations_ClassLevelRequiresPermissions() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new ClassLevelRequiresPermissions();
        Method method = target.getClass().getMethod("requiresPermissions1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelRequiresPermissions.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(RequiresPermissions.class);

        assertThat(((RequiresPermissions) annotation).value()).containsOnly("octopus1:*:*");

    }

    @Test
    public void getAllAnnotations_ClassLevelRequiresUser() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new ClassLevelRequiresUser();
        Method method = target.getClass().getMethod("requiresUser1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelRequiresUser.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(RequiresUser.class);
    }

    @Test
    public void getAllAnnotations_ClassLevelSystemAccount() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new ClassLevelSystemAccount();
        Method method = target.getClass().getMethod("systemAccount1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelSystemAccount.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);

        Annotation annotation = annotations.getClassAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(SystemAccount.class);

        assertThat(((SystemAccount) annotation).value()).containsOnly("account1");

    }

    @Test
    public void getAllAnnotations_MethodLevelPermitAll() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("permitAll");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(PermitAll.class);

    }

    @Test
    public void getAllAnnotations_MethodLevelNoAnnotation() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("noAnnotation");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).isEmpty();

    }

    @Test
    public void getAllAnnotations_MethodLevelRequiresUser() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("requiresUser");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(RequiresUser.class);

    }

    @Test
    public void getAllAnnotations_MethodLevelOnlyDuringAuthentication() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthentication");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(OnlyDuringAuthentication.class);

    }

    @Test
    public void getAllAnnotations_MethodLevelOnlyDuringAuthorization() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("inAuthorization");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(OnlyDuringAuthorization.class);

    }

    @Test
    public void getAllAnnotations_MethodLevelTestPermissionCheck() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("permission2");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(TestPermissionCheck.class);

        assertThat(((TestPermissionCheck) annotation).value()).containsOnly(TestPermission.PERMISSION2);
    }

    @Test
    public void getAllAnnotations_MethodLevelCustomVoterCheck() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("customVoter");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(CustomVoterCheck.class);

        assertThat(((CustomVoterCheck) annotation).value()).containsOnly(TestCustomVoter.class);
    }

    @Test
    public void getAllAnnotations_MethodLevelRequiresPermissions() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("requiresPermission2");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(RequiresPermissions.class);

        assertThat(((RequiresPermissions) annotation).value()).containsOnly("octopus2:*:*");
    }

    @Test
    public void getAllAnnotations_MethodLevelSystemAccount() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("systemAccountValue2");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(SystemAccount.class);

        assertThat(((SystemAccount) annotation).value()).containsOnly("account2");
    }

    @Test
    public void getAllAnnotations_MethodLevelOctopusPermissions_1() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("octopusPermission1");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(RequiresPermissions.class);

        assertThat(((RequiresPermissions) annotation).value()).containsOnly("permissionName");
    }

    @Test
    public void getAllAnnotations_MethodLevelCustomCheck() throws NoSuchMethodException {
        when(octopusConfigMock.getCustomCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                return MyCheck.class;
            }
        });

        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("customExtended");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        Annotation annotation = annotations.getMethodAnnotations().iterator().next();

        assertThat(annotation).isInstanceOf(MyCheck.class);

        assertThat(((MyCheck) annotation).info()).isEqualTo(MyCheckInfo.EXTENDED);
    }

    @Test
    public void getAllAnnotations_MultipleAtMethodLevel() throws NoSuchMethodException {
        beanManagerFake.endRegistration();
        Object target = new MultipleAtMethodLevel();
        Method method = target.getClass().getMethod("multiple");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MultipleAtMethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(2);

        // I assume that the correct ones are retrieved
    }

    @Test
    public void getAllAnnotations_MethodLevelAdditional() throws NoSuchMethodException {
        AnnotationsToFind mock = Mockito.mock(AnnotationsToFind.class);
        beanManagerFake.registerBean(mock, AnnotationsToFind.class);
        beanManagerFake.endRegistration();

        List<Class<? extends Annotation>> extraAnnotations = new ArrayList<>();
        extraAnnotations.add(AdditionalAnnotation.class);
        when(mock.getList()).thenReturn(extraAnnotations);
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("additionalAnnotation");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getMethodAnnotations()).hasSize(1);
        Annotation annotation = annotations.getMethodAnnotations().iterator().next();
        assertThat(annotation.annotationType()).isEqualTo(AdditionalAnnotation.class);
    }

    @Test
    public void getAllAnnotations_ClassLevelAdditional() throws NoSuchMethodException {
        AnnotationsToFind mock = Mockito.mock(AnnotationsToFind.class);
        beanManagerFake.registerBean(mock, AnnotationsToFind.class);
        beanManagerFake.endRegistration();

        List<Class<? extends Annotation>> extraAnnotations = new ArrayList<>();
        extraAnnotations.add(AdditionalAnnotation.class);
        when(mock.getList()).thenReturn(extraAnnotations);
        Object target = new ClassLevelAdditionalAnnotation();
        Method method = target.getClass().getMethod("additionalAnnotation");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, ClassLevelAdditionalAnnotation.class, method);
        assertThat(annotations.getMethodAnnotations()).isEmpty();
        assertThat(annotations.getClassAnnotations()).hasSize(1);
        Annotation annotation = annotations.getClassAnnotations().iterator().next();
        assertThat(annotation.annotationType()).isEqualTo(AdditionalAnnotation.class);
    }

    @Test
    public void getStringValues_singleValue_NoArrayBased() throws NoSuchMethodException {
        when(octopusConfigMock.getCustomCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                return MyCheck.class;
            }
        });

        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("getStringValue1Bis");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        String[] values = AnnotationUtil.getStringValues(annotations.getMethodAnnotations().iterator().next());
        assertThat(values).containsOnly("value1Bis");
    }

    @Test
    public void getAdvancedFlag_notPresent() throws NoSuchMethodException {
        when(octopusConfigMock.getCustomCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                return MyCheck.class;
            }
        });

        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("getStringValue1Bis");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        boolean advanced = AnnotationUtil.hasAdvancedFlag(annotations.getMethodAnnotations().iterator().next());
        assertThat(advanced).isFalse();
    }

    @Test
    public void getAdvancedFlag_WithFlag() throws NoSuchMethodException {
        when(octopusConfigMock.getCustomCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                return MyAdvancedCheck.class;
            }
        });

        beanManagerFake.endRegistration();
        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("getDataWithAdvancedChecks");

        AnnotationInfo annotations = AnnotationUtil.getAllAnnotations(octopusConfigMock, MethodLevel.class, method);
        assertThat(annotations.getClassAnnotations()).isEmpty();
        assertThat(annotations.getMethodAnnotations()).hasSize(1);

        boolean advanced = AnnotationUtil.hasAdvancedFlag(annotations.getMethodAnnotations().iterator().next());
        assertThat(advanced).isTrue();
    }

}