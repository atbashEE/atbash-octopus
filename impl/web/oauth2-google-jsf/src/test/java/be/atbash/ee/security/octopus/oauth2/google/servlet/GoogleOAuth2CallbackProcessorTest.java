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
package be.atbash.ee.security.octopus.oauth2.google.servlet;

import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.ee.security.octopus.oauth2.info.OAuth2InfoProvider;
import be.atbash.ee.security.octopus.oauth2.servlet.OAuth2SessionAttributesUtil;
import be.atbash.ee.security.octopus.session.Session;
import be.atbash.ee.security.octopus.session.SessionUtil;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.SavedRequest;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class GoogleOAuth2CallbackProcessorTest {

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
    private HttpServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @InjectMocks
    private GoogleOAuth2CallbackProcessor processor;

    @Captor
    private ArgumentCaptor<String> redirectStringCaptor;

    private TestLogger logger = TestLoggerFactory.getTestLogger(GoogleOAuth2CallbackProcessor.class);

    @AfterEach
    public void clearLoggers() {
        TestLoggerFactory.clear();
    }

    @Test
    public void processCallback() throws IOException, ExecutionException, InterruptedException {
        when(sessionAttributesUtilMock.getCSRFToken(requestMock)).thenReturn("csrfToken");
        when(requestMock.getParameter("state")).thenReturn("csrfToken");
        when(requestMock.getParameter("error")).thenReturn(null);

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

        processor.processCallback(requestMock, responseMock);

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

    @Test
    public void processCallback_failedCSRFCheck() throws IOException {
        when(sessionAttributesUtilMock.getCSRFToken(requestMock)).thenReturn("correctCsrfToken");
        when(requestMock.getParameter("state")).thenReturn("WrongCsrfToken");
        when(requestMock.getParameter("error")).thenReturn(null);

        when(requestMock.getSession()).thenReturn(httpSessionMock);
        when(requestMock.getContextPath()).thenReturn("/root");

        processor.processCallback(requestMock, responseMock);

        // invalidated session since a new authentication is attempted
        verify(httpSessionMock).invalidate();

        // Removal of SavedRequest is important to end login redirection.
        verifyNoMoreInteractions(sessionMock);

        verify(responseMock).sendRedirect(redirectStringCaptor.capture());
        assertThat(redirectStringCaptor.getValue()).isEqualTo("/root");

        // Important for the authentication process of Octopus.
        verify(webSubjectMock, never()).login(any(AuthenticationToken.class));

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("The CSRF token does not match (session correctCsrfToken - request WrongCsrfToken)");
    }

    @Test
    public void processCallback_failedGoogleAuthentication() throws IOException, ExecutionException, InterruptedException {

        when(requestMock.getParameter("error")).thenReturn("access_denied");

        when(requestMock.getSession()).thenReturn(httpSessionMock);
        when(requestMock.getContextPath()).thenReturn("/root");

        processor.processCallback(requestMock, responseMock);

        // invalidated session since a new authentication is attempted
        verify(httpSessionMock).invalidate();

        // Do not retrieve info from session (like CSRF data)
        verifyNoMoreInteractions(sessionAttributesUtilMock);

        // Removal of SavedRequest is important to end login redirection.
        verifyNoMoreInteractions(sessionMock);

        verify(responseMock).sendRedirect(redirectStringCaptor.capture());
        assertThat(redirectStringCaptor.getValue()).isEqualTo("/root");

        // Important for the authentication process of Octopus.
        verify(webSubjectMock, never()).login(any(AuthenticationToken.class));

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Google informs us that no valid credentials are supplied or that consent is not given");

    }
}