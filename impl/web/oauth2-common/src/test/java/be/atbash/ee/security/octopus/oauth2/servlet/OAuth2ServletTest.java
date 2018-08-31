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

import be.atbash.ee.security.octopus.oauth2.csrf.CSRFTokenProducer;
import be.atbash.ee.security.octopus.oauth2.provider.OAuth2ServiceProducer;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OAuth2ServletTest {

    @Mock
    private CSRFTokenProducer csrfTokenProducerMock;

    @Mock
    private OAuth2SessionAttributesUtil sessionAttributesUtilMock;

    @InjectMocks
    private DummyServlet servlet;

    @Mock
    private HttpServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @Mock
    private OAuth20Service oauth20ServiceMock;

    @Captor
    private ArgumentCaptor<String> redirectStringCaptor;

    private DummyProducer serviceProducer;

    @Test
    public void redirectToAuthorizationURL() throws IOException {
        serviceProducer = new DummyProducer(oauth20ServiceMock);

        when(csrfTokenProducerMock.nextToken()).thenReturn("csrfToken");

        when(oauth20ServiceMock.getAuthorizationUrl()).thenReturn("http://auth.server/root/login");

        servlet.redirectToAuthorizationURL(requestMock, responseMock, serviceProducer);

        verify(responseMock).sendRedirect(redirectStringCaptor.capture());
        assertThat(redirectStringCaptor.getValue()).isEqualTo("http://auth.server/root/login");

        verify(sessionAttributesUtilMock).setCSRFToken(requestMock, "csrfToken");
        verify(sessionAttributesUtilMock).setOAuth2Service(requestMock, oauth20ServiceMock);

    }

    public static class DummyServlet extends OAuth2Servlet {
    }

    public static class DummyProducer extends OAuth2ServiceProducer {
        private OAuth20Service auth20Service;

        DummyProducer(OAuth20Service auth20Service) {

            this.auth20Service = auth20Service;
        }

        @Override
        public OAuth20Service createOAuthService(HttpServletRequest req, String csrfToken) {
            return auth20Service;
        }
    }
}