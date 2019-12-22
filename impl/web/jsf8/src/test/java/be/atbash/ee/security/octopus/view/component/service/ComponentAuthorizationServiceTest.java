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
package be.atbash.ee.security.octopus.view.component.service;

import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.Combined;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.StringPermissionLookupFixture;
import be.atbash.ee.security.octopus.authz.permission.role.RolePermission;
import be.atbash.ee.security.octopus.authz.permission.typesafe.RoleLookup;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.view.component.secured.SecuredComponentData;
import be.atbash.ee.security.octopus.view.component.secured.SecuredComponentDataParameter;
import be.atbash.util.BeanManagerFake;
import org.apache.deltaspike.security.api.authorization.AbstractAccessDecisionVoter;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class ComponentAuthorizationServiceTest {

    private static final String MY_PERMISSION = "myPermission";
    private static final String NOT_MY_PERMISSION = "notMyPermission";
    private static final String MY_ROLE = "myRole";
    private static final String NOT_MY_ROLE = "notMyRole";

    private ComponentAuthorizationService service;

    private BeanManagerFake beanManagerFake;

    @Mock
    private AbstractAccessDecisionVoter myPermissionVoterMock;

    @Mock
    private AbstractAccessDecisionVoter notMyPermissionVoterMock;

    @Mock
    private AbstractAccessDecisionVoter myRoleVoterMock;

    @Mock
    private AbstractAccessDecisionVoter notMyRoleVoterMock;

    @Mock
    private Subject subjectMock;

    @Mock
    private SecurityViolation securityViolationMock;

    @Mock
    private SecurityViolationInfoProducer securityViolationInfoProducerMock;

    @Before
    public void setup() {
        service = new ComponentAuthorizationService();

        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(MY_PERMISSION, myPermissionVoterMock);
        beanManagerFake.registerBean(NOT_MY_PERMISSION, notMyPermissionVoterMock);
        beanManagerFake.registerBean(MY_ROLE, myRoleVoterMock);
        beanManagerFake.registerBean(NOT_MY_ROLE, notMyRoleVoterMock);

        beanManagerFake.registerBean(subjectMock, Subject.class);
        beanManagerFake.registerBean(securityViolationInfoProducerMock, SecurityViolationInfoProducer.class);

        when(myPermissionVoterMock.checkPermission(ArgumentMatchers.any(AccessDecisionVoterContext.class))).thenReturn(new HashSet<SecurityViolation>());

        Set<SecurityViolation> violations = new HashSet<>();
        violations.add(securityViolationMock);
        when(notMyPermissionVoterMock.checkPermission(ArgumentMatchers.any(AccessDecisionVoterContext.class))).thenReturn(violations);

        when(myRoleVoterMock.checkPermission(ArgumentMatchers.any(AccessDecisionVoterContext.class))).thenReturn(new HashSet<SecurityViolation>());

        violations = new HashSet<>();
        violations.add(securityViolationMock);
        when(notMyRoleVoterMock.checkPermission(ArgumentMatchers.any(AccessDecisionVoterContext.class))).thenReturn(violations);

    }

    private void finishSetup() {
        beanManagerFake.endRegistration();
        service.init();
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void hasAccess_true() {
        finishSetup();

        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData("myPermission", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isTrue();
    }

    @Test
    public void hasAccess_Inverted() {
        finishSetup();

        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData("myPermission", true, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isFalse();
    }

    @Test
    public void hasAccess_false() {
        finishSetup();

        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData("notMyPermission", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isFalse();
    }

    @Test
    public void hasAccess_multiple_CombinedOr() {
        finishSetup();

        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData("notMyPermission,myPermission", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isTrue();
    }

    @Test
    public void hasAccess_multiple_CombinedAnd() {
        finishSetup();

        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData("notMyPermission,myPermission", false, Combined.AND, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isFalse();
    }

    @Test
    public void hasAccess_wildcardPermission() {
        finishSetup();

        configureSubjectPermissionCheck("JUnit:*:*");
        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData("JUnit:*:*", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isTrue();
    }

    private void configureSubjectPermissionCheck(final String wildcardPermission) {
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                NamedDomainPermission permission = (NamedDomainPermission) invocation.getArguments()[0];
                if (!wildcardPermission.equalsIgnoreCase(permission.getWildcardNotation())) {
                    throw new AuthorizationException();
                }
                return null;
            }
        }).when(subjectMock).checkPermission(ArgumentMatchers.any(NamedDomainPermission.class));

        //Mockito.doThrow(new AuthorizationException("Role not authorized")).when(subjectMock).checkPermission(any(NamedApplicationRole.class));
    }

    private void configureSubjectRoleCheck(final String roleName) {
        Mockito.doAnswer(new Answer() {
            @Override
            public Object answer(InvocationOnMock invocation) throws Throwable {
                RolePermission rolePermission = (RolePermission) invocation.getArguments()[0];
                if (!roleName.equalsIgnoreCase(rolePermission.getRoleName())) {
                    throw new AuthorizationException();
                }
                return null;
            }
        }).when(subjectMock).checkPermission(ArgumentMatchers.any(RolePermission.class));

        //Mockito.doThrow(new AuthorizationException("Role not authorized")).when(subjectMock).checkPermission(any(NamedDomainPermission.class));
    }

    @Test
    public void hasAccess_wildcardPermission_NoAccess() {
        finishSetup();

        configureSubjectPermissionCheck("other:*:*");

        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData("JUnit:*:*", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isFalse();
    }

    @Test
    public void hasAccess_StringPermission_NoMapping() {
        finishSetup();

        configureSubjectPermissionCheck("somePermission:*:*");
        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData(":somePermission", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isTrue();
    }

    @Test
    public void hasAccess_StringPermission_NoMapping_NoAccess() {
        finishSetup();

        configureSubjectPermissionCheck("other:*:*");

        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData(":somePermission", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isFalse();
    }

    @Test
    public void hasAccess_StringPermission_Mapping() throws IllegalAccessException {
        StringPermissionLookupFixture.registerLookup(beanManagerFake);

        finishSetup();

        configureSubjectPermissionCheck("SPermission:1:*");
        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData(":permission1", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isTrue();
    }

    @Test
    public void hasAccess_StringPermission_Mapping_NoAccess() throws IllegalAccessException {
        StringPermissionLookupFixture.registerLookup(beanManagerFake);

        finishSetup();

        configureSubjectPermissionCheck("SPermission:1:*");
        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData(":permission2", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isFalse();
    }

    @Test
    public void hasAccess_rolePermission_NoMapping() {

        finishSetup();

        configureSubjectRoleCheck("role1");
        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData("::role1", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isTrue();
    }

    @Test
    public void hasAccess_rolePermission_NoMapping_NoAccess() {

        finishSetup();

        configureSubjectRoleCheck("role2");
        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData("::role1", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isFalse();
    }

    @Test
    public void hasAccess_rolePermission_Mapping() {
        RoleLookup roleLookupMock = Mockito.mock(RoleLookup.class);
        beanManagerFake.registerBean(roleLookupMock, RoleLookup.class);

        finishSetup();

        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData("myRole", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isTrue();
    }

    @Test
    public void hasAccess_rolePermission_Mapping_NoAccess() {
        RoleLookup roleLookupMock = Mockito.mock(RoleLookup.class);
        beanManagerFake.registerBean(roleLookupMock, RoleLookup.class);

        finishSetup();

        SecuredComponentDataParameter[] parameters = new SecuredComponentDataParameter[0];
        SecuredComponentData data = new SecuredComponentData("notMyRole", false, Combined.OR, parameters, null);

        boolean access = service.hasAccess(data);
        assertThat(access).isFalse();
    }

}