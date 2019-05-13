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
package be.atbash.ee.security.octopus.mgt;

import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.realm.OctopusOfflineRealm;
import be.atbash.ee.security.octopus.subject.*;
import be.atbash.ee.security.octopus.subject.support.DelegatingSubject;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class StandardSecurityManagerTest {

    @Mock
    private SubjectFactory subjectFactoryMock;

    @Mock
    private OctopusOfflineRealm octopusRealmMock;

    private StandardSecurityManager securityManager;

    @Captor
    private ArgumentCaptor<SubjectContext> subjectContextArgumentCaptor;

    @Before
    public void setup() {
        securityManager = new StandardSecurityManager(subjectFactoryMock, octopusRealmMock);
    }

    @Test
    public void login() {

        Subject subject = new DelegatingSubject(null, true, new StandardSecurityManager(subjectFactoryMock, octopusRealmMock), octopusRealmMock);
        when(subjectFactoryMock.createSubject(any(SubjectContext.class))).thenReturn(subject);

        AuthenticationToken token = new UsernamePasswordToken("Atbash", "secret");
        AuthenticationInfo info = new AuthenticationInfo(new UserPrincipal("id", "atbash", "Atbash"), "credentials");

        when(octopusRealmMock.authenticate(token)).thenReturn(info);

        Subject data = securityManager.login(null, token);

        assertThat(data).isNotNull();

        verify(subjectFactoryMock).createSubject(subjectContextArgumentCaptor.capture());

        SubjectContext subjectContext = subjectContextArgumentCaptor.getValue();
        assertThat(subjectContext.isAuthenticated()).isTrue();
        assertThat(subjectContext.getSecurityManager()).isEqualTo(securityManager);
        assertThat(subjectContext.getAuthenticationToken()).isEqualTo(token);
        assertThat(subjectContext.getAuthenticationInfo()).isEqualTo(info);

        assertThat(data).isEqualTo(subject);
    }

    @Test(expected = AuthenticationException.class)
    public void login_authenticationException() {

        AuthenticationToken token = new UsernamePasswordToken("Atbash", "secret");

        when(octopusRealmMock.authenticate(token)).thenThrow(new AuthenticationException());

        try {
            securityManager.login(null, token);
        } finally {
            verifyNoMoreInteractions(subjectFactoryMock);
        }

        // FIXME test onFailedLogin event when implemented
    }

    @Test
    public void logout() {
        PrincipalCollection principals = new PrincipalCollection(new UserPrincipal("id", "atbash", "Atbash"));
        Subject subject = new DelegatingSubject(principals, true, new StandardSecurityManager(subjectFactoryMock, octopusRealmMock), octopusRealmMock);

        securityManager.logout(subject);

        verify(octopusRealmMock).onLogout(principals);
    }

    @Test
    public void logout_NoPrincipal() {
        Subject subject = new DelegatingSubject(null, true, new StandardSecurityManager(subjectFactoryMock, octopusRealmMock), octopusRealmMock);

        securityManager.logout(subject);

        verifyNoMoreInteractions(octopusRealmMock);
    }
}