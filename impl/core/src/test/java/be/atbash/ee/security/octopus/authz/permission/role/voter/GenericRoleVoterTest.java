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
package be.atbash.ee.security.octopus.authz.permission.role.voter;

import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.permission.role.ApplicationRole;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.apache.deltaspike.security.api.authorization.AccessDecisionState;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class GenericRoleVoterTest {
    private BeanManagerFake beanManagerFake;

    @Mock
    private Subject subjectMock;

    @Mock
    private SecurityViolationInfoProducer securityViolationInfoProducerMock;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(subjectMock, Subject.class);
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void checkPermission_createInstance() {
        beanManagerFake.endRegistration();

        ApplicationRole role = new ApplicationRole("JUnit");
        GenericRoleVoter voter = GenericRoleVoter.createInstance(role);

        AccessDecisionVoterContext context = new GenericRoleVoterTest.TestContext();
        Set<SecurityViolation> violations = voter.checkPermission(context);
        assertThat(violations).isNotNull();
        assertThat(violations).isEmpty();

        verify(subjectMock).checkPermission(any(Permission.class)); // We can assume it is the permission we used in the createInstance
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void checkPermission_createInstance_illegalSetNamedPermission() {
        beanManagerFake.endRegistration();

        ApplicationRole role = new ApplicationRole("JUnit");
        GenericRoleVoter voter = GenericRoleVoter.createInstance(role);
        voter.setNamedRole(role);
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void checkPermission_createInstance_nullPermission() {
        beanManagerFake.endRegistration();

        GenericRoleVoter.createInstance((ApplicationRole) null);
    }

    @Test
    public void checkPermission_createInstance_exception() {
        beanManagerFake.registerBean(securityViolationInfoProducerMock, SecurityViolationInfoProducer.class);
        beanManagerFake.endRegistration();

        Mockito.doThrow(new AuthorizationException()).when(subjectMock).checkPermission(any(Permission.class));
        when(securityViolationInfoProducerMock.getViolationInfo(any(AccessDecisionVoterContext.class), any(Permission.class))).thenReturn("Permission(Role) violated");

        ApplicationRole role = new ApplicationRole("JUnit");
        GenericRoleVoter voter = GenericRoleVoter.createInstance(role);

        AccessDecisionVoterContext context = new GenericRoleVoterTest.TestContext();
        Set<SecurityViolation> violations = voter.checkPermission(context);
        assertThat(violations).isNotNull();
        assertThat(violations).extracting("reason").containsExactly("Permission(Role) violated");

        verify(subjectMock).checkPermission(any(Permission.class)); // We can assume it is the permission we used in the createInstane
    }

    @Test
    public void checkPermission_newInstance() {
        beanManagerFake.endRegistration();

        ApplicationRole role = new ApplicationRole("JUnit");
        GenericRoleVoter voter = new GenericRoleVoter();
        voter.setNamedRole(role);

        AccessDecisionVoterContext context = new GenericRoleVoterTest.TestContext();
        Set<SecurityViolation> violations = voter.checkPermission(context);
        assertThat(violations).isNotNull();
        assertThat(violations).isEmpty();

        verify(subjectMock).checkPermission(any(Permission.class)); // We can assume it is the permission we used in the createInstane
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void checkPermission_newInstance_missingSetNamedPermission() {
        beanManagerFake.endRegistration();

        GenericRoleVoter voter = new GenericRoleVoter();

        AccessDecisionVoterContext context = new GenericRoleVoterTest.TestContext();
        voter.checkPermission(context);
    }

    @Test
    public void checkPermission_newInstance_exception() {
        beanManagerFake.registerBean(securityViolationInfoProducerMock, SecurityViolationInfoProducer.class);
        beanManagerFake.endRegistration();

        Mockito.doThrow(new AuthorizationException()).when(subjectMock).checkPermission(any(Permission.class));
        when(securityViolationInfoProducerMock.getViolationInfo(any(AccessDecisionVoterContext.class), any(Permission.class))).thenReturn("Permission(Role) violated");

        ApplicationRole role = new ApplicationRole("JUnit");
        GenericRoleVoter voter = new GenericRoleVoter();
        voter.setNamedRole(role);

        AccessDecisionVoterContext context = new GenericRoleVoterTest.TestContext();
        Set<SecurityViolation> violations = voter.checkPermission(context);
        assertThat(violations).isNotNull();
        assertThat(violations).extracting("reason").containsExactly("Permission(Role) violated");

        verify(subjectMock).checkPermission(any(Permission.class)); // We can assume it is the permission we used in the createInstane
    }

    private class TestContext implements AccessDecisionVoterContext {

        @Override
        public AccessDecisionState getState() {
            return null;
        }

        @Override
        public List<SecurityViolation> getViolations() {
            return null;
        }

        @Override
        public <T> T getSource() {
            return null;
        }

        @Override
        public Map<String, Object> getMetaData() {
            return null;
        }

        @Override
        public <T> T getMetaDataFor(String s, Class<T> aClass) {
            return null;
        }

    }
}