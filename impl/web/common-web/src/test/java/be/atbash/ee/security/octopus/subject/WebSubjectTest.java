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
package be.atbash.ee.security.octopus.subject;

import be.atbash.ee.security.octopus.mgt.WebSecurityManager;
import be.atbash.ee.security.octopus.session.Session;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class WebSubjectTest {

    @Mock
    private WebSecurityManager webSecurityManagerMock;

    @Mock
    private Session sessionMock;

    @Test
    public void logout() {
        // Test that logout performs
        // - logout on WebSecurityManager
        // - sets null to PrincipalCollection
        // - Session
        // - authenticated -> false
        UserPrincipal userPrincipal = new UserPrincipal(123L, "Atbash", "Atbash");
        WebSubject subject = new WebSubject(new PrincipalCollection(userPrincipal),
                true, false, null, sessionMock, webSecurityManagerMock);

        assertThat(subject.getPrincipals()).isNotNull();
        assertThat(subject.getSession(false)).isNotNull();
        assertThat(subject.isAuthenticated()).isTrue();

        subject.logout();

        verify(webSecurityManagerMock).logout(subject);

        assertThat(subject.getPrincipals()).isNull();
        assertThat(subject.getSession(false)).isNull();
        assertThat(subject.isAuthenticated()).isFalse();
        assertThat(subject.isRemembered()).isFalse();
    }
}