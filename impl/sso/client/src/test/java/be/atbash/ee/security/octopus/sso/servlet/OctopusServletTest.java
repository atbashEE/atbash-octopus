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
package be.atbash.ee.security.octopus.sso.servlet;

import be.atbash.ee.security.octopus.sso.ClientCallbackHelper;
import be.atbash.ee.security.octopus.sso.config.OctopusSSOClientConfiguration;
import be.atbash.ee.security.octopus.sso.core.client.SSOFlow;
import be.atbash.ee.security.octopus.util.URLUtil;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class OctopusServletTest {

    @Mock
    private URLUtil urlUtilMock;

    @Mock
    private OctopusSSOClientConfiguration octopusSSOClientConfigurationMock;

    @InjectMocks
    private OctopusServlet octopusServlet;

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private HttpSession httpSessionMock;

    @Mock
    private ClientCallbackHelper clientCallbackHelperMock;

    @Captor
    private ArgumentCaptor<String> stringArgumentCaptor;

    private BeanManagerFake beanManagerFake = new BeanManagerFake();

    @AfterEach
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void redirectToLogin() throws ServletException, IOException {

        beanManagerFake.endRegistration();
        octopusServlet.init();

        when(octopusSSOClientConfigurationMock.getSSOClientId()).thenReturn("clientId");
        when(octopusSSOClientConfigurationMock.getSSOType()).thenReturn(SSOFlow.AUTHORIZATION_CODE);
        when(octopusSSOClientConfigurationMock.getSSOScopes()).thenReturn("");
        when(octopusSSOClientConfigurationMock.getLoginPage()).thenReturn("http://sso.server.org/root");

        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);

        when(urlUtilMock.determineRoot(any(HttpServletRequest.class))).thenReturn("http://client.app/base");

        octopusServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());

        String loginUrl = stringArgumentCaptor.getValue();

        assertThat(loginUrl).startsWith("http://sso.server.org/root");
        assertThat(loginUrl).contains("response_type=code");
        assertThat(loginUrl).contains("client_id=clientId");
        assertThat(loginUrl).contains("redirect_uri=http%3A%2F%2Fclient.app%2Fbase%2Fsso%2FSSOCallback");
        assertThat(loginUrl).contains("scope=openid+octopus");
        assertThat(loginUrl).contains("&state=");
        assertThat(loginUrl).contains("&nonce=");

        verify(urlUtilMock).determineRoot(any(HttpServletRequest.class));

    }


    @Test
    public void redirectToLogin_manualDetermined() throws ServletException, IOException {
        beanManagerFake.registerBean(clientCallbackHelperMock, ClientCallbackHelper.class);
        beanManagerFake.endRegistration();
        octopusServlet.init();

        when(octopusSSOClientConfigurationMock.getSSOClientId()).thenReturn("clientId");
        when(octopusSSOClientConfigurationMock.getSSOType()).thenReturn(SSOFlow.AUTHORIZATION_CODE);
        when(octopusSSOClientConfigurationMock.getSSOScopes()).thenReturn("");
        when(octopusSSOClientConfigurationMock.getLoginPage()).thenReturn("http://sso.server.org/root");

        when(httpServletRequestMock.getSession(true)).thenReturn(httpSessionMock);

        when(clientCallbackHelperMock.determineCallbackRoot(any(HttpServletRequest.class))).thenReturn("http://manual.url/root");

        octopusServlet.doGet(httpServletRequestMock, httpServletResponseMock);

        verify(httpServletResponseMock).sendRedirect(stringArgumentCaptor.capture());

        String loginUrl = stringArgumentCaptor.getValue();

        assertThat(loginUrl).startsWith("http://sso.server.org/root");
        assertThat(loginUrl).contains("response_type=code");
        assertThat(loginUrl).contains("client_id=clientId");
        assertThat(loginUrl).contains("redirect_uri=http%3A%2F%2Fmanual.url%2Froot%2Fsso%2FSSOCallback");
        assertThat(loginUrl).contains("scope=openid+octopus");
        assertThat(loginUrl).contains("&state=");
        assertThat(loginUrl).contains("&nonce=");

        verify(urlUtilMock, never()).determineRoot(any(HttpServletRequest.class));

    }

}