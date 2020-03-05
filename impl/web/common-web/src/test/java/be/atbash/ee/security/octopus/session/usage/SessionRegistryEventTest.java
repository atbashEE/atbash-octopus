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
package be.atbash.ee.security.octopus.session.usage;

import be.atbash.ee.security.octopus.subject.UserPrincipal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class SessionRegistryEventTest {

    @Mock
    private HttpServletRequest servletRequestMock;

    @Mock
    private HttpSession sessionMock;

    @Test
    public void getSessionId_fromSessionId() {
        SessionRegistryEvent event = new SessionRegistryEvent("theSessionId");
        assertThat(event.getSessionId()).isEqualTo("theSessionId");

        event = new SessionRegistryEvent("theSessionId", null, null);
        // UserPrincipal and AuthenticationToken not important in this test
        assertThat(event.getSessionId()).isEqualTo("theSessionId");
    }

    @Test
    public void getSessionId_fromServletRequest() {
        when(servletRequestMock.getSession()).thenReturn(sessionMock);
        when(sessionMock.getId()).thenReturn("theSessionId");
        UserPrincipal userPrincipal = new UserPrincipal(1L, "junit", "JUnit");
        SessionRegistryEvent event = new SessionRegistryEvent(servletRequestMock, userPrincipal);

        assertThat(event.getSessionId()).isEqualTo("theSessionId");
    }

    @Test
    public void getSessionId_fromSession() {
        when(sessionMock.getId()).thenReturn("theSessionId");
        SessionRegistryEvent event = new SessionRegistryEvent(sessionMock, UserAction.LOGON);

        assertThat(event.getSessionId()).isEqualTo("theSessionId");
    }

    @Test
    public void getActionEvent_fromSessionId() {
        SessionRegistryEvent event = new SessionRegistryEvent("theSessionId");
        assertThat(event.getUserAction()).isEqualTo(UserAction.LOGOUT);
    }

    @Test
    public void getActionEvent_fromMultiple() {

        SessionRegistryEvent event = new SessionRegistryEvent("theSessionId", null, null);

        assertThat(event.getUserAction()).isEqualTo(UserAction.LOGON);
    }

    @Test
    public void getActionEvent_fromServletRequest() {
        UserPrincipal userPrincipal = new UserPrincipal(1L, "junit", "JUnit");
        SessionRegistryEvent event = new SessionRegistryEvent(servletRequestMock, userPrincipal);

        assertThat(event.getUserAction()).isEqualTo(UserAction.REMEMBER_ME_LOGON);
    }
}