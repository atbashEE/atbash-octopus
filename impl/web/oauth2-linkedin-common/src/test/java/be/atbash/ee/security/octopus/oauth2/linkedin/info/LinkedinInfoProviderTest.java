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
package be.atbash.ee.security.octopus.oauth2.linkedin.info;

import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.ee.security.octopus.oauth2.linkedin.json.LinkedinJSONProcessor;
import be.atbash.ee.security.octopus.oauth2.linkedin.provider.LinkedinOAuth2ServiceProducer;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.oauth.OAuth20Service;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.concurrent.ExecutionException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class LinkedinInfoProviderTest {

    @Mock
    private LinkedinOAuth2ServiceProducer serviceProducerMock;

    @Mock
    private LinkedinJSONProcessor jsonProcessorMock;

    @Mock
    private OAuth20Service oauthServiceMock;

    @Mock
    private Response responseMock;

    @Mock
    private HttpServletRequest servletRequestMock;

    @InjectMocks
    private LinkedinInfoProvider infoProvider;

    @Test
    public void retrieveUserInfo() throws InterruptedException, ExecutionException, IOException {
        configureMocks();
        when(jsonProcessorMock.extractLinkedinUser(anyString())).thenReturn(new OAuth2UserToken());

        OAuth2AccessToken token = new OAuth2AccessToken("access", "raw");

        OAuth2UserToken userToken = infoProvider.retrieveUserInfo(token, servletRequestMock);

        assertThat(userToken).isNotNull();
        assertThat(userToken.getToken()).isEqualTo(token);
    }

    private void configureMocks() throws InterruptedException, ExecutionException, IOException {
        when(serviceProducerMock.createOAuthService(servletRequestMock, null)).thenReturn(oauthServiceMock);
        when(oauthServiceMock.execute(any(OAuthRequest.class))).thenReturn(responseMock);
        when(responseMock.getBody()).thenReturn("Google User Info JSON");

    }

    @Test(expected = UnauthenticatedException.class)
    public void retrieveUserInfo_unauthenticated() throws InterruptedException, ExecutionException, IOException {
        configureMocks();
        when(jsonProcessorMock.extractLinkedinUser(anyString())).thenThrow(UnauthenticatedException.class);

        OAuth2AccessToken token = new OAuth2AccessToken("access", "raw");

        infoProvider.retrieveUserInfo(token, servletRequestMock);
    }

    @Test(expected = AtbashUnexpectedException.class)
    public void retrieveUserInfo_unexpected() throws InterruptedException, ExecutionException, IOException {
        configureMocks();
        when(jsonProcessorMock.extractLinkedinUser(anyString())).thenThrow(AtbashUnexpectedException.class);

        OAuth2AccessToken token = new OAuth2AccessToken("access", "raw");

        infoProvider.retrieveUserInfo(token, servletRequestMock);
    }

    @Test(expected = AtbashUnexpectedException.class)
    public void retrieveUserInfo_IOException() throws InterruptedException, ExecutionException, IOException {
        when(serviceProducerMock.createOAuthService(servletRequestMock, null)).thenReturn(oauthServiceMock);
        when(oauthServiceMock.execute(any(OAuthRequest.class))).thenThrow(IOException.class);

        OAuth2AccessToken token = new OAuth2AccessToken("access", "raw");

        try {
            infoProvider.retrieveUserInfo(token, servletRequestMock);
        } finally {
            verify(jsonProcessorMock, never()).extractLinkedinUser(anyString());
        }
    }


}