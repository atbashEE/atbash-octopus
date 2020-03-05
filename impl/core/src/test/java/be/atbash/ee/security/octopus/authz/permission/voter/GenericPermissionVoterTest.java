/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.authz.permission.voter;

import be.atbash.ee.security.octopus.authz.AuthorizationException;
import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.Permission;
import be.atbash.ee.security.octopus.authz.violation.SecurityViolationInfoProducer;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.exception.AtbashIllegalActionException;
import org.apache.deltaspike.security.api.authorization.AccessDecisionState;
import org.apache.deltaspike.security.api.authorization.AccessDecisionVoterContext;
import org.apache.deltaspike.security.api.authorization.SecurityViolation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

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
@ExtendWith(MockitoExtension.class)
public class GenericPermissionVoterTest {

    private BeanManagerFake beanManagerFake;

    @Mock
    private Subject subjectMock;

    @Mock
    private SecurityViolationInfoProducer securityViolationInfoProducerMock;

    @BeforeEach
    public void setup() {
        beanManagerFake = new BeanManagerFake();
        beanManagerFake.registerBean(subjectMock, Subject.class);
    }

    @AfterEach
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void checkPermission_createInstance() {
        beanManagerFake.endRegistration();

        NamedDomainPermission permission = new NamedDomainPermission("JUnit", "junit:*:*");
        GenericPermissionVoter voter = GenericPermissionVoter.createInstance(permission);

        AccessDecisionVoterContext context = new TestContext();
        Set<SecurityViolation> violations = voter.checkPermission(context);
        assertThat(violations).isNotNull();
        assertThat(violations).isEmpty();

        verify(subjectMock).checkPermission(any(Permission.class)); // We can assume it is the permission we used in the createInstance
    }

    @Test
    public void checkPermission_createInstance_illegalSetNamedPermission() {
        beanManagerFake.endRegistration();

        NamedDomainPermission permission = new NamedDomainPermission("JUnit", "junit:*:*");
        GenericPermissionVoter voter = GenericPermissionVoter.createInstance(permission);
        Assertions.assertThrows(AtbashIllegalActionException.class, () -> voter.setNamedPermission(permission));
    }

    @Test
    public void checkPermission_createInstance_nullPermission() {
        beanManagerFake.endRegistration();

        Assertions.assertThrows(AtbashIllegalActionException.class, () -> GenericPermissionVoter.createInstance(null));
    }

    @Test
    public void checkPermission_createInstance_exception() {
        beanManagerFake.registerBean(securityViolationInfoProducerMock, SecurityViolationInfoProducer.class);
        beanManagerFake.endRegistration();

        Mockito.doThrow(new AuthorizationException()).when(subjectMock).checkPermission(any(Permission.class));
        when(securityViolationInfoProducerMock.getViolationInfo(any(AccessDecisionVoterContext.class), any(Permission.class))).thenReturn("Permission violated");

        NamedDomainPermission permission = new NamedDomainPermission("JUnit", "junit:*:*");
        GenericPermissionVoter voter = GenericPermissionVoter.createInstance(permission);

        AccessDecisionVoterContext context = new TestContext();
        Set<SecurityViolation> violations = voter.checkPermission(context);
        assertThat(violations).isNotNull();
        assertThat(violations).extracting("reason").containsExactly("Permission violated");

        verify(subjectMock).checkPermission(any(Permission.class)); // We can assume it is the permission we used in the createInstane
    }

    @Test
    public void checkPermission_newInstance() {
        beanManagerFake.endRegistration();

        NamedDomainPermission permission = new NamedDomainPermission("JUnit", "junit:*:*");
        GenericPermissionVoter voter = new GenericPermissionVoter();
        voter.setNamedPermission(permission);

        AccessDecisionVoterContext context = new TestContext();
        Set<SecurityViolation> violations = voter.checkPermission(context);
        assertThat(violations).isNotNull();
        assertThat(violations).isEmpty();

        verify(subjectMock).checkPermission(any(Permission.class)); // We can assume it is the permission we used in the createInstane
    }

    @Test
    public void checkPermission_newInstance_missingSetNamedPermission() {
        beanManagerFake.endRegistration();

        GenericPermissionVoter voter = new GenericPermissionVoter();

        AccessDecisionVoterContext context = new TestContext();
        Assertions.assertThrows(AtbashIllegalActionException.class, () -> voter.checkPermission(context));
    }

    @Test
    public void checkPermission_newInstance_exception() {
        beanManagerFake.registerBean(securityViolationInfoProducerMock, SecurityViolationInfoProducer.class);
        beanManagerFake.endRegistration();

        Mockito.doThrow(new AuthorizationException()).when(subjectMock).checkPermission(any(Permission.class));
        when(securityViolationInfoProducerMock.getViolationInfo(any(AccessDecisionVoterContext.class), any(Permission.class))).thenReturn("Permission violated");

        NamedDomainPermission permission = new NamedDomainPermission("JUnit", "junit:*:*");
        GenericPermissionVoter voter = new GenericPermissionVoter();
        voter.setNamedPermission(permission);

        AccessDecisionVoterContext context = new TestContext();
        Set<SecurityViolation> violations = voter.checkPermission(context);
        assertThat(violations).isNotNull();
        assertThat(violations).extracting("reason").containsExactly("Permission violated");

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