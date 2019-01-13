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
package be.atbash.ee.security.octopus.oauth2.linkedin.provider;

import be.atbash.ee.security.octopus.oauth2.config.OAuth2Configuration;
import be.atbash.ee.security.octopus.util.URLUtil;
import be.atbash.util.TestReflectionUtils;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class LinkedinOAuth2ServiceProducerTest {

    @Mock
    private OAuth2Configuration configurationMock;

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @InjectMocks
    private LinkedinOAuth2ServiceProducer serviceProducer;

    @Before
    public void setup() throws IllegalAccessException {
        TestReflectionUtils.injectDependencies(serviceProducer, new URLUtil());
    }

    @Test
    public void createOAuthService() {
        defineRoot();
        when(configurationMock.getClientId()).thenReturn("clientId");
        when(configurationMock.getClientSecret()).thenReturn("clientSecret");
        when(configurationMock.getOAuth2Scopes()).thenReturn("");
        OAuth20Service service = serviceProducer.createOAuthService(httpServletRequestMock, "CSRF");
        assertThat(service.getAuthorizationUrl()).isEqualTo("https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=clientId&redirect_uri=http%3A%2F%2Fsome.server%2Foidc%2Foauth2callback&scope=r_basicprofile%20r_emailaddress%20&state=CSRF");
    }

    @Test
    public void createOAuthService_additionalScopes() {
        defineRoot();
        when(configurationMock.getClientId()).thenReturn("clientId");
        when(configurationMock.getClientSecret()).thenReturn("clientSecret");
        when(configurationMock.getOAuth2Scopes()).thenReturn("ScopeX");
        OAuth20Service service = serviceProducer.createOAuthService(httpServletRequestMock, "CSRF");
        assertThat(service.getAuthorizationUrl()).isEqualTo("https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=clientId&redirect_uri=http%3A%2F%2Fsome.server%2Foidc%2Foauth2callback&scope=r_basicprofile%20r_emailaddress%20ScopeX&state=CSRF");
    }

    @Test
    public void createOAuthService_NoCSRF() {
        defineRoot();
        when(configurationMock.getClientId()).thenReturn("clientId");
        when(configurationMock.getClientSecret()).thenReturn("clientSecret");
        when(configurationMock.getOAuth2Scopes()).thenReturn("");
        OAuth20Service service = serviceProducer.createOAuthService(httpServletRequestMock, " ");
        assertThat(service.getAuthorizationUrl()).isEqualTo("https://www.linkedin.com/oauth/v2/authorization?response_type=code&client_id=clientId&redirect_uri=http%3A%2F%2Fsome.server%2Foidc%2Foauth2callback&scope=r_basicprofile%20r_emailaddress%20");
    }

    private void defineRoot() {
        when(httpServletRequestMock.getScheme()).thenReturn("http");
        when(httpServletRequestMock.getServerName()).thenReturn("some.server");
        when(httpServletRequestMock.getServerPort()).thenReturn(80);
        when(httpServletRequestMock.getContextPath()).thenReturn("/oidc");

    }
}