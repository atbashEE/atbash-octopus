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
package be.atbash.ee.security.octopus.provider;

import be.atbash.ee.security.octopus.authz.annotation.RequiresPermissions;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.StringPermissionLookup;
import be.atbash.ee.security.octopus.authz.permission.typesafe.PermissionLookup;
import be.atbash.ee.security.octopus.authz.permission.voter.GenericPermissionVoter;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.names.VoterNameFactory;
import be.atbash.ee.security.octopus.provider.testclasses.TestPermissionAnnotation;
import be.atbash.ee.security.octopus.provider.testclasses.TestPermissionAnnotationCheck;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.TestReflectionUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.enterprise.inject.spi.Annotated;
import java.lang.annotation.Annotation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class NamedPermissionProducerTest extends AbstractProducerTest {

    public static final String TEST_PERMISSION = "testPermission";

    @Mock
    private Annotated annotatedMock;

    @Mock
    private TestPermissionAnnotationCheck testPermissionAnnotationCheckMock;

    @Mock
    private RequiresPermissions requiresPermissionsMock;

    @Mock
    private VoterNameFactory voterNameFactoryMock;

    @Mock
    private PermissionLookup permissionLookupMock;

    @Mock
    private StringPermissionLookup stringPermissionLookupMock;

    private OctopusCoreConfiguration configMock;

    private BeanManagerFake beanManagerFake;

    private GenericPermissionVoter correctPermissionVoter;

    @InjectMocks
    private NamedPermissionProducer producer;

    @Before
    public void setUp() {

        when(injectionPointMock.getAnnotated()).thenReturn(annotatedMock);

        beanManagerFake = new BeanManagerFake();
        correctPermissionVoter = new GenericPermissionVoter();
    }

    private void registerOctopusConfig(Class<? extends Annotation> namedPermissionCheckClass) throws IllegalAccessException {
        configMock = new OctopusConfigMock(namedPermissionCheckClass);
        TestReflectionUtils.injectDependencies(producer, configMock);
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void getVoter() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(testPermissionAnnotationCheckMock);

        when(testPermissionAnnotationCheckMock.value()).thenReturn(new TestPermissionAnnotation[]{TestPermissionAnnotation.TEST});
        when(voterNameFactoryMock.generatePermissionBeanName("TEST")).thenReturn("testVoter");
        beanManagerFake.registerBean("testVoter", correctPermissionVoter);
        beanManagerFake.endRegistration();

        GenericPermissionVoter voter = producer.getVoter(injectionPointMock);

        assertThat(voter).isEqualTo(correctPermissionVoter);
    }

    @Test
    public void getVoter_NoAnnotation() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(null);

        // @Rule at AbstractProducerTest
        checkUnsatisfiedResolutionException();
        producer.getVoter(injectionPointMock);

    }

    @Test
    public void getVoter_MultipleValues() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(testPermissionAnnotationCheckMock);

        when(testPermissionAnnotationCheckMock.value()).thenReturn(new TestPermissionAnnotation[]{TestPermissionAnnotation.TEST, TestPermissionAnnotation.SECOND});

        // @Rule at AbstractProducerTest
        checkAmbigousResolutionException();

        producer.getVoter(injectionPointMock);
    }

    @Test
    public void getVoter_WithRequiresPermission() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(null);
        when(annotatedMock.getAnnotation(RequiresPermissions.class)).thenReturn(requiresPermissionsMock);

        when(requiresPermissionsMock.value()).thenReturn(new String[]{TEST_PERMISSION});

        when(stringPermissionLookupMock.getPermission(TEST_PERMISSION)).thenReturn(new NamedDomainPermission(TEST_PERMISSION, "test:*:*"));

        Subject subjectMock = mock(Subject.class);
        beanManagerFake.registerBean(subjectMock, Subject.class);

        beanManagerFake.endRegistration();

        GenericPermissionVoter voter = producer.getVoter(injectionPointMock);

        assertThat(voter).isNotEqualTo(correctPermissionVoter);  // Because we need to test that BeanManager isn't used.

        voter.verifyPermission();

        ArgumentCaptor<NamedDomainPermission> argument = ArgumentCaptor.forClass(NamedDomainPermission.class);
        verify(subjectMock).isPermitted(argument.capture());
        assertThat(argument.getValue().getName()).isEqualTo(TEST_PERMISSION);
    }

    @Test
    public void getVoter_WithRequiresPermission_version2() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(RequiresPermissions.class)).thenReturn(requiresPermissionsMock);

        when(requiresPermissionsMock.value()).thenReturn(new String[]{TEST_PERMISSION});

        when(stringPermissionLookupMock.getPermission(TEST_PERMISSION)).thenReturn(new NamedDomainPermission(TEST_PERMISSION, "test:*:*"));

        Subject subjectMock = mock(Subject.class);
        beanManagerFake.registerBean(subjectMock, Subject.class);

        beanManagerFake.endRegistration();

        GenericPermissionVoter voter = producer.getVoter(injectionPointMock);

        assertThat(voter).isNotEqualTo(correctPermissionVoter);  // Because we need to test that BeanManager isn't used.

        voter.verifyPermission();

        ArgumentCaptor<NamedDomainPermission> argument = ArgumentCaptor.forClass(NamedDomainPermission.class);
        verify(subjectMock).isPermitted(argument.capture());
        assertThat(argument.getValue().getName()).isEqualTo(TEST_PERMISSION);
    }

    @Test
    public void getVoter_NoInfoAtAll() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(RequiresPermissions.class)).thenReturn(null);

        // @Rule at AbstractProducerTest
        checkUnsatisfiedResolutionException();
        producer.getVoter(injectionPointMock);

    }

    @Test
    public void getVoter_WithOctopusPermission_MultipleValues() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(RequiresPermissions.class)).thenReturn(requiresPermissionsMock);

        when(requiresPermissionsMock.value()).thenReturn(new String[]{TEST_PERMISSION, "SecondPermission"});

        // @Rule at AbstractProducerTest
        checkAmbigousResolutionException();

        producer.getVoter(injectionPointMock);
    }

    @Test
    public void getPermission() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(testPermissionAnnotationCheckMock);

        when(testPermissionAnnotationCheckMock.value()).thenReturn(new TestPermissionAnnotation[]{TestPermissionAnnotation.TEST});

        NamedDomainPermission namedDomainPermission = new NamedDomainPermission("test", "test:junit:*");
        when(permissionLookupMock.getPermission(TestPermissionAnnotation.TEST.name())).thenReturn(namedDomainPermission);

        NamedDomainPermission permission = producer.getPermission(injectionPointMock);
        assertThat(permission).isEqualTo(namedDomainPermission);
    }

    @Test
    public void getPermission_NoAnnotation() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(null);

        // @Rule at AbstractProducerTest
        checkUnsatisfiedResolutionException();
        producer.getPermission(injectionPointMock);

    }

    @Test
    public void getPermission_MultipleValues() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(testPermissionAnnotationCheckMock);

        when(testPermissionAnnotationCheckMock.value()).thenReturn(new TestPermissionAnnotation[]{TestPermissionAnnotation.TEST, TestPermissionAnnotation.SECOND});

        // @Rule at AbstractProducerTest
        checkAmbigousResolutionException();
        producer.getPermission(injectionPointMock);
    }

    @Test
    public void getPermission_withRequiresPermission() throws IllegalAccessException {
        registerOctopusConfig(TestPermissionAnnotationCheck.class);
        when(annotatedMock.getAnnotation(TestPermissionAnnotationCheck.class)).thenReturn(null);
        when(annotatedMock.getAnnotation(RequiresPermissions.class)).thenReturn(requiresPermissionsMock);

        when(requiresPermissionsMock.value()).thenReturn(new String[]{TEST_PERMISSION});

        when(stringPermissionLookupMock.getPermission(TEST_PERMISSION)).thenReturn(new NamedDomainPermission(TEST_PERMISSION, "test:*:*"));

        NamedDomainPermission permission = producer.getPermission(injectionPointMock);
        assertThat(permission.getWildcardNotation()).isEqualTo("test:*:*");
    }

    @Test
    public void getPermission_NoInfoAtAll() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(RequiresPermissions.class)).thenReturn(null);

        // @Rule at AbstractProducerTest
        checkUnsatisfiedResolutionException();
        producer.getPermission(injectionPointMock);

    }

    @Test
    public void getPermission_WithOctopusPermission_MultipleValues() throws IllegalAccessException {
        registerOctopusConfig(null);
        when(annotatedMock.getAnnotation(RequiresPermissions.class)).thenReturn(requiresPermissionsMock);

        when(requiresPermissionsMock.value()).thenReturn(new String[]{TEST_PERMISSION, "SecondPermission"});

        // @Rule at AbstractProducerTest
        checkAmbigousResolutionException();
        producer.getPermission(injectionPointMock);
    }

    private static class OctopusConfigMock extends OctopusCoreConfiguration {

        private Class<? extends Annotation> namedPermissionCheckClass;

        public OctopusConfigMock(Class<? extends Annotation> namedPermissionCheckClass) {
            this.namedPermissionCheckClass = namedPermissionCheckClass;
        }

        @Override
        public Class<? extends Annotation> getNamedPermissionCheckClass() {
            return namedPermissionCheckClass;

        }
    }

}