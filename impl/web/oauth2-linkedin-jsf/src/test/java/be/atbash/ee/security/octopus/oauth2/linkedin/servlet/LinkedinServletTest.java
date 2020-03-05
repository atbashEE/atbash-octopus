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
package be.atbash.ee.security.octopus.oauth2.linkedin.servlet;

import be.atbash.ee.security.octopus.oauth2.csrf.CSRFTokenProducer;
import be.atbash.ee.security.octopus.oauth2.linkedin.provider.LinkedinOAuth2ServiceProducer;
import be.atbash.ee.security.octopus.oauth2.servlet.OAuth2SessionAttributesUtil;
import com.github.scribejava.core.oauth.OAuth20Service;
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
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class LinkedinServletTest {

    @Mock
    private CSRFTokenProducer csrfTokenProducerMock;

    @Mock
    private OAuth2SessionAttributesUtil sessionAttributesUtilMock;

    @Mock
    private LinkedinOAuth2ServiceProducer linkedinOAuth2ServiceProducerMock;

    @Mock
    private OAuth20Service oauth20ServiceMock;

    @Mock
    private HttpServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @InjectMocks
    private LinkedinServlet linkedinServlet;

    @Captor
    private ArgumentCaptor<String> redirectStringCaptor;

    @Test
    public void doGet() throws IOException, ServletException {

        when(csrfTokenProducerMock.nextToken()).thenReturn("csrfToken");

        when(linkedinOAuth2ServiceProducerMock.createOAuthService(requestMock, "csrfToken")).thenReturn(oauth20ServiceMock);
        when(oauth20ServiceMock.getAuthorizationUrl()).thenReturn("http://auth.server/root/login");

        linkedinServlet.doGet(requestMock, responseMock);

        verify(responseMock).sendRedirect(redirectStringCaptor.capture());
        assertThat(redirectStringCaptor.getValue()).isEqualTo("http://auth.server/root/login");

        verify(sessionAttributesUtilMock).setCSRFToken(requestMock, "csrfToken");
        verify(sessionAttributesUtilMock).setOAuth2Service(requestMock, oauth20ServiceMock);
    }
}