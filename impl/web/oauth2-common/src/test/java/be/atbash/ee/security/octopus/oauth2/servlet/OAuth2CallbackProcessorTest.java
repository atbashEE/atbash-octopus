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
package be.atbash.ee.security.octopus.oauth2.servlet;

import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.ee.security.octopus.oauth2.info.OAuth2InfoProvider;
import be.atbash.ee.security.octopus.session.Session;
import be.atbash.ee.security.octopus.session.SessionUtil;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.SavedRequest;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2CallbackProcessorTest {

    @Mock
    private OAuth2InfoProvider infoProviderMock;

    @Mock
    private SessionUtil sessionUtilMock;

    @Mock
    private OAuth2SessionAttributesUtil sessionAttributesUtilMock;

    @Mock
    private OAuth20Service oauth20ServiceMock;

    @Mock
    private WebSubject webSubjectMock;

    @Mock
    private Session sessionMock;

    @Mock
    private HttpSession httpSessionMock;

    @Mock
    private OctopusJSFConfiguration jsfConfigurationMock;

    @InjectMocks
    private DummyOAuth2CallbackProcessor processor;

    @Mock
    private HttpServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @Captor
    private ArgumentCaptor<String> redirectStringCaptor;

    @Captor
    private ArgumentCaptor<String> parameterStringCaptor;

    @Captor
    private ArgumentCaptor<Object> parameterValueCaptor;

    private TestLogger logger = TestLoggerFactory.getTestLogger(DummyOAuth2CallbackProcessor.class);

    @After
    public void clearLoggers() {
        TestLoggerFactory.clear();
    }

    @Test
    public void checkCSRFToken() throws IOException {
        when(sessionAttributesUtilMock.getCSRFToken(requestMock)).thenReturn("csrfToken");
        when(requestMock.getParameter("state")).thenReturn("csrfToken");

        processor.checkCSRFToken(requestMock, responseMock);

        verify(responseMock, never()).sendRedirect(anyString());

        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void checkCSRFToken_failed() throws IOException {
        when(sessionAttributesUtilMock.getCSRFToken(requestMock)).thenReturn("correctCsrfToken");
        when(requestMock.getParameter("state")).thenReturn("WrongCsrfToken");

        when(requestMock.getSession()).thenReturn(httpSessionMock);
        when(requestMock.getContextPath()).thenReturn("/root");

        processor.checkCSRFToken(requestMock, responseMock);

        verify(responseMock).sendRedirect(redirectStringCaptor.capture());
        assertThat(redirectStringCaptor.getValue()).isEqualTo("/root");

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("The CSRF token does not match (session correctCsrfToken - request WrongCsrfToken)");

    }

    @Test
    public void doAuthenticate() throws IOException, ExecutionException, InterruptedException {

        when(sessionAttributesUtilMock.getOAuth2Service(requestMock)).thenReturn(oauth20ServiceMock);
        when(requestMock.getParameter("code")).thenReturn("authorizationCode");
        OAuth2AccessToken accessToken = new OAuth2AccessToken("accessToken");
        when(oauth20ServiceMock.getAccessToken("authorizationCode")).thenReturn(accessToken);

        OAuth2UserToken userToken = new OAuth2UserToken();
        when(infoProviderMock.retrieveUserInfo(accessToken, requestMock)).thenReturn(userToken);

        when(requestMock.getRequestURI()).thenReturn("original.jsf");

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getSession(false)).thenReturn(sessionMock);
        when(webSubjectMock.getSession()).thenReturn(sessionMock);
        SavedRequest savedRequest = new SavedRequest(requestMock);
        when(sessionMock.getAttribute("octopusSavedRequest")).thenReturn(savedRequest);

        processor.doAuthenticate(requestMock, responseMock, infoProviderMock);

        // Before actually logging the user in, a new Http session must be started
        verify(sessionUtilMock).invalidateCurrentSession(requestMock);

        // Removal of SavedRequest is important to end login redirection.
        verify(sessionMock).removeAttribute("octopusSavedRequest");

        verify(responseMock).sendRedirect(redirectStringCaptor.capture());
        assertThat(redirectStringCaptor.getValue()).isEqualTo("original.jsf");

        // Important for the authentication process of Octopus.
        verify(webSubjectMock).login(userToken);

        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test(expected = IOException.class)
    public void doAuthenticate_ErrorAccessCode() throws IOException, ExecutionException, InterruptedException {

        when(sessionAttributesUtilMock.getOAuth2Service(requestMock)).thenReturn(oauth20ServiceMock);
        when(requestMock.getParameter("code")).thenReturn("authorizationCode");
        OAuth2AccessToken accessToken = new OAuth2AccessToken("accessToken");
        when(oauth20ServiceMock.getAccessToken("authorizationCode")).thenThrow(new IOException());


        try {
            processor.doAuthenticate(requestMock, responseMock, infoProviderMock);
        } finally {

            // Before actually logging the user in, a new Http session must be started
            verify(sessionUtilMock, never()).invalidateCurrentSession(requestMock);

            // Removal of SavedRequest is important to end login redirection.
            verify(sessionMock, never()).removeAttribute("octopusSavedRequest");

            verify(responseMock, never()).sendRedirect(anyString());

            // Important for the authentication process of Octopus.
            verify(webSubjectMock, never()).login(any(AuthenticationToken.class));

            assertThat(logger.getLoggingEvents()).isEmpty();

            verify(infoProviderMock, never()).retrieveUserInfo(accessToken, requestMock);
        }
    }

    @Test
    public void doAuthenticate_authenticationException() throws IOException, ExecutionException, InterruptedException {

        when(sessionAttributesUtilMock.getOAuth2Service(requestMock)).thenReturn(oauth20ServiceMock);
        when(requestMock.getParameter("code")).thenReturn("authorizationCode");
        OAuth2AccessToken accessToken = new OAuth2AccessToken("accessToken");
        when(oauth20ServiceMock.getAccessToken("authorizationCode")).thenReturn(accessToken);

        OAuth2UserToken userToken = new OAuth2UserToken();
        when(infoProviderMock.retrieveUserInfo(accessToken, requestMock)).thenReturn(userToken);

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getSession(false)).thenReturn(sessionMock);
        when(webSubjectMock.getSession()).thenReturn(sessionMock);
        SavedRequest savedRequest = new SavedRequest(requestMock);
        when(sessionMock.getAttribute("octopusSavedRequest")).thenReturn(savedRequest);

        when(requestMock.getSession()).thenReturn(httpSessionMock);

        when(requestMock.getContextPath()).thenReturn("/root");
        when(jsfConfigurationMock.getUnauthorizedExceptionPage()).thenReturn("/unauthorized.jsf");

        doThrow(new AuthenticationException("Authentication exception for test")).when(webSubjectMock).login(userToken);

        try {
            processor.doAuthenticate(requestMock, responseMock, infoProviderMock);
        } finally {

            // Before actually logging the user in, a new Http session must be started
            verify(sessionUtilMock).invalidateCurrentSession(requestMock);

            // Removal of SavedRequest is important to end login redirection.
            verify(sessionMock).removeAttribute(anyString());

            //verify(httpSessionMock).setAttribute(OAuth2UserToken.OAUTH2_USER_INFO, userToken);
            verify(httpSessionMock, times(2)).setAttribute(parameterStringCaptor.capture(), parameterValueCaptor.capture());

            assertThat(parameterStringCaptor.getAllValues().get(0)).isEqualTo(OAuth2UserToken.OAUTH2_USER_INFO);
            assertThat(parameterValueCaptor.getAllValues().get(0)).isEqualTo(userToken);

            assertThat(parameterStringCaptor.getAllValues().get(1)).isEqualTo("AuthenticationExceptionMessage");
            assertThat(parameterValueCaptor.getAllValues().get(1)).isEqualTo("Authentication exception for test");

            verify(webSubjectMock).login(userToken);

            verify(responseMock).sendRedirect(redirectStringCaptor.capture());
            assertThat(redirectStringCaptor.getValue()).isEqualTo("/root/unauthorized.jsf");

            // Important for the authentication process of Octopus.

            assertThat(logger.getLoggingEvents()).isEmpty();
        }
    }

    public static class DummyOAuth2CallbackProcessor extends OAuth2CallbackProcessor {

        @Override
        public void processCallback(HttpServletRequest request, HttpServletResponse response) throws IOException {

        }
    }
}