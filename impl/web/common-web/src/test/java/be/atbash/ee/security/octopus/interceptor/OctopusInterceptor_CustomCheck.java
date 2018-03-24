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

import be.atbash.ee.security.octopus.authz.checks.*;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.PermissionResolver;
import be.atbash.ee.security.octopus.authz.permission.WildcardPermission;
import be.atbash.ee.security.octopus.authz.permission.voter.AbstractGenericVoter;
import be.atbash.ee.security.octopus.authz.violation.BasicAuthorizationViolation;
import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.config.names.VoterNameFactory;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.ee.security.octopus.interceptor.annotation.AnnotationInfo;
import be.atbash.ee.security.octopus.interceptor.testclasses.MethodLevel;
import be.atbash.ee.security.octopus.interceptor.testclasses.MyCheck;
import be.atbash.ee.security.octopus.realm.AuthorizingRealm;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.TestReflectionUtils;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.interceptor.InvocationContext;
import java.lang.reflect.Method;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Fail.fail;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OctopusInterceptor_CustomCheck {

    private BeanManagerFake beanManagerFake;

    @Mock
    private OctopusCoreConfiguration octopusConfigMock;

    @Mock
    private SecurityViolationInfoProducer infoProducerMock;

    @Mock
    private Subject subjectMock;

    @Mock
    private AbstractGenericVoter abstractGenericVoterMock;

    @Mock
    private PermissionResolver permissionResolverMock;

    @Mock
    private AuthorizingRealm realmMock;

    @InjectMocks
    protected OctopusInterceptor octopusInterceptor;

    private VoterNameFactory voterNameFactory;

    @Captor
    private ArgumentCaptor<AccessDecisionVoterContext> accessDecisionVoterCaptor;

    @Before
    public void setup() throws IllegalAccessException {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(octopusConfigMock, OctopusCoreConfiguration.class);

        // SecurityViolationInfoProducer mock instance assigned to CDI and playback
        //beanManagerFake.registerBean(infoProducerMock, SecurityViolationInfoProducer.class);

        voterNameFactory = new VoterNameFactory();
        TestReflectionUtils.injectDependencies(voterNameFactory, octopusConfigMock);
        when(octopusConfigMock.getCustomCheckSuffix()).thenReturn("AccessDecissionVoter");

        Permission permission = new WildcardPermission("Permission1:*:*");
        when(permissionResolverMock.resolvePermission("Permission1")).thenReturn(permission);
        SecurityCheckCustomCheck securityCheckCustomCheck = new SecurityCheckCustomCheck();
        TestReflectionUtils.injectDependencies(securityCheckCustomCheck, infoProducerMock, octopusConfigMock, voterNameFactory, permissionResolverMock, realmMock);

        beanManagerFake.registerBean(securityCheckCustomCheck, SecurityCheck.class);

        beanManagerFake.registerBean("myCheckAccessDecissionVoter", abstractGenericVoterMock);

        // Define the Custom check class
        when(octopusConfigMock.getCustomCheckClass()).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) {
                return MyCheck.class;
            }
        });

        ThreadContext.bind(subjectMock);

    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void testAuthenticated_validCheck() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("customBasic");
        InvocationContext context = new TestInvocationContext(target, method);

        finishSetup();

        // authenticated
        when(subjectMock.isAuthenticated()).thenReturn(Boolean.TRUE);

        when(abstractGenericVoterMock.checkPermission(any(AccessDecisionVoterContext.class))).thenReturn(new HashSet<SecurityViolation>());

        octopusInterceptor.interceptForSecurity(context);

        verify(abstractGenericVoterMock).checkPermission(accessDecisionVoterCaptor.capture());

        AccessDecisionVoterContext voterContext = accessDecisionVoterCaptor.getValue();
        OctopusInvocationContext invocationContext = voterContext.getSource();
        // Test to make sure the AnnotationInfo is passed into the contextData
        assertThat(invocationContext.getContextData()).hasSize(1);
        assertThat(invocationContext.getContextData()).containsOnlyKeys(AnnotationInfo.class.getName());

    }

    @Test(expected = SecurityAuthorizationViolationException.class)
    public void testAuthenticated_NotValidCheck() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("customBasic");
        InvocationContext context = new TestInvocationContext(target, method);

        finishSetup();

        // authenticated
        when(subjectMock.isAuthenticated()).thenReturn(Boolean.TRUE);

        HashSet<SecurityViolation> violations = new HashSet<>();
        violations.add(new BasicAuthorizationViolation("JUnit", null));
        when(abstractGenericVoterMock.checkPermission(any(AccessDecisionVoterContext.class))).thenReturn(violations);

        try {
            octopusInterceptor.interceptForSecurity(context);
            fail("Should fail");
        } finally {

            verify(abstractGenericVoterMock).checkPermission(accessDecisionVoterCaptor.capture());
        }

    }

    @Test(expected = SecurityAuthorizationViolationException.class)
    public void testNotAuthenticated() throws Exception {

        Object target = new MethodLevel();
        Method method = target.getClass().getMethod("customBasic");
        InvocationContext context = new TestInvocationContext(target, method);

        finishSetup();

        //when(infoProducerMock.getViolationInfo(any(AccessDecisionVoterContext.class), any(NamedDomainPermission.class))).thenReturn("Violation Info");
        //when(infoProducerMock.getViolationInfo(any(AccessDecisionVoterContext.class))).thenReturn("Violation Info");
        //when(infoProducerMock.defineViolation(any(InvocationContext.class), any(Permission.class))).thenReturn(new BasicAuthorizationViolation("X", "Y"));

        // NOT authenticated
        when(subjectMock.isAuthenticated()).thenReturn(Boolean.FALSE);

        /*
        HashSet<SecurityViolation> violations = new HashSet<>();
        violations.add(new BasicAuthorizationViolation("JUnit", null));
        when(abstractGenericVoterMock.checkPermission(any(AccessDecisionVoterContext.class))).thenReturn(violations);
        */

        try {
            octopusInterceptor.interceptForSecurity(context);
        } finally {

            verify(abstractGenericVoterMock, never()).checkPermission(accessDecisionVoterCaptor.capture());
        }

    }

    protected void finishSetup() throws IllegalAccessException {

        beanManagerFake.endRegistration();

        AnnotationAuthorizationChecker authorizationChecker = new AnnotationAuthorizationChecker();

        AnnotationCheckFactory checkFactory = new AnnotationCheckFactory();
        checkFactory.init();

        SecurityCheckDataFactory securityCheckDataFactory = new SecurityCheckDataFactory();
        TestReflectionUtils.injectDependencies(securityCheckDataFactory, octopusConfigMock);

        TestReflectionUtils.injectDependencies(authorizationChecker, checkFactory, securityCheckDataFactory);

        TestReflectionUtils.injectDependencies(octopusInterceptor, authorizationChecker);
    }

}
