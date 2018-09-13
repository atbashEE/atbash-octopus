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
package be.atbash.ee.security.octopus.oauth2.google.servlet;

import be.atbash.ee.security.octopus.oauth2.config.jsf.OAuth2JSFConfiguration;
import be.atbash.ee.security.octopus.oauth2.csrf.CSRFTokenProducer;
import be.atbash.ee.security.octopus.oauth2.google.provider.GoogleOAuth2ServiceProducer;
import be.atbash.ee.security.octopus.oauth2.servlet.OAuth2SessionAttributesUtil;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class GoogleServletTest {

    @Mock
    private CSRFTokenProducer csrfTokenProducerMock;

    @Mock
    private OAuth2SessionAttributesUtil sessionAttributesUtilMock;

    @Mock
    private GoogleOAuth2ServiceProducer googleOAuth2ServiceProducerMock;

    @Mock
    private OAuth2JSFConfiguration oAuth2ConfigurationMock;

    @Mock
    private OAuth20Service oauth20ServiceMock;

    @Mock
    private HttpServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @InjectMocks
    private GoogleServlet googleServlet;

    @Captor
    private ArgumentCaptor<String> redirectStringCaptor;

    @Test
    public void doGet() throws IOException, ServletException {

        when(csrfTokenProducerMock.nextToken()).thenReturn("csrfToken");

        when(googleOAuth2ServiceProducerMock.createOAuthService(requestMock, "csrfToken")).thenReturn(oauth20ServiceMock);
        when(oauth20ServiceMock.getAuthorizationUrl()).thenReturn("http://auth.server/root/login");

        googleServlet.doGet(requestMock, responseMock);

        verify(responseMock).sendRedirect(redirectStringCaptor.capture());
        assertThat(redirectStringCaptor.getValue()).isEqualTo("http://auth.server/root/login");

        verify(sessionAttributesUtilMock).setCSRFToken(requestMock, "csrfToken");
        verify(sessionAttributesUtilMock).setOAuth2Service(requestMock, oauth20ServiceMock);
    }

    @Test
    public void doGet_multipleAccount_Cookie() throws IOException, ServletException {

        when(csrfTokenProducerMock.nextToken()).thenReturn("csrfToken");

        when(googleOAuth2ServiceProducerMock.createOAuthService(requestMock, "csrfToken")).thenReturn(oauth20ServiceMock);
        when(oauth20ServiceMock.getAuthorizationUrl()).thenReturn("http://auth.server/root/login");

        Cookie cookie = new Cookie("OctopusGoogleMultipleAccounts", "true");
        Cookie[] cookies = new Cookie[]{cookie};
        when(requestMock.getCookies()).thenReturn(cookies);

        googleServlet.doGet(requestMock, responseMock);

        verify(responseMock).sendRedirect(redirectStringCaptor.capture());
        assertThat(redirectStringCaptor.getValue()).isEqualTo("http://auth.server/root/login&prompt=select_account");

        verify(sessionAttributesUtilMock).setCSRFToken(requestMock, "csrfToken");
        verify(sessionAttributesUtilMock).setOAuth2Service(requestMock, oauth20ServiceMock);
    }

    @Test
    public void doGet_Cookie_notMultipleAccount() throws IOException, ServletException {

        when(csrfTokenProducerMock.nextToken()).thenReturn("csrfToken");

        when(googleOAuth2ServiceProducerMock.createOAuthService(requestMock, "csrfToken")).thenReturn(oauth20ServiceMock);
        when(oauth20ServiceMock.getAuthorizationUrl()).thenReturn("http://auth.server/root/login");

        Cookie cookie = new Cookie("someCookie", "true");
        Cookie[] cookies = new Cookie[]{cookie};
        when(requestMock.getCookies()).thenReturn(cookies);

        googleServlet.doGet(requestMock, responseMock);

        verify(responseMock).sendRedirect(redirectStringCaptor.capture());
        assertThat(redirectStringCaptor.getValue()).isEqualTo("http://auth.server/root/login");

        verify(sessionAttributesUtilMock).setCSRFToken(requestMock, "csrfToken");
        verify(sessionAttributesUtilMock).setOAuth2Service(requestMock, oauth20ServiceMock);
    }

    @Test
    public void doGet_MultipleAccount_forced() throws IOException, ServletException {

        when(csrfTokenProducerMock.nextToken()).thenReturn("csrfToken");

        when(googleOAuth2ServiceProducerMock.createOAuthService(requestMock, "csrfToken")).thenReturn(oauth20ServiceMock);
        when(oauth20ServiceMock.getAuthorizationUrl()).thenReturn("http://auth.server/root/login");

        when(oAuth2ConfigurationMock.getForceGoogleAccountSelection()).thenReturn(true);
        googleServlet.doGet(requestMock, responseMock);

        verify(responseMock).sendRedirect(redirectStringCaptor.capture());
        assertThat(redirectStringCaptor.getValue()).isEqualTo("http://auth.server/root/login&prompt=select_account");

        verify(sessionAttributesUtilMock).setCSRFToken(requestMock, "csrfToken");
        verify(sessionAttributesUtilMock).setOAuth2Service(requestMock, oauth20ServiceMock);

        verify(requestMock, never()).getCookies();
    }
}