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
package be.atbash.ee.security.octopus.server.requestor;

import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.server.config.OctopusServerConfiguration;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.util.TestReflectionUtils;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.CommonContentTypes;
import net.jadler.Jadler;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.security.SecureRandom;

import static net.jadler.Jadler.onRequest;
import static net.jadler.Jadler.port;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class TokenRequestorTest {

    @Mock
    private OctopusCoreConfiguration octopusCoreConfigurationMock;

    @Mock
    private OctopusServerConfiguration octopusServerConfigurationMock;

    private TokenRequestor requestor;

    @Before
    public void setUp() throws NoSuchFieldException {
        Jadler.initJadler();
        // TokenRequestor is a singleton.
        TestReflectionUtils.resetOf(TokenRequestor.class, "INSTANCE");
    }

    @After
    public void tearDown() {
        Jadler.closeJadler();
    }

    @Test
    public void getToken_withClientIdAndSecret() {

        defineSecret(32);
        when(octopusServerConfigurationMock.getTokenEndpoint()).thenReturn("http://localhost:" + port() + "/oidc/token");
        when(octopusServerConfigurationMock.getSSOClientId()).thenReturn("JUnit_client");

        onRequest()
                .havingPathEqualTo("/oidc/token")
                .havingBody(new BodyMatcher(true))
                .respond()
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"token_type\":\"bearer\", \"access_token\":\"TheAccessCode\"}");
        // Init uses the octopusCoreConfigurationMock, so that needs to be mocked first
        requestor = TokenRequestor.getInstance(octopusCoreConfigurationMock, octopusServerConfigurationMock);

        UsernamePasswordToken usernamePassword = new UsernamePasswordToken("JUnit", "SecretValue");
        TokenResponse token = requestor.getToken(usernamePassword);

        assertThat(token.indicatesSuccess()).isTrue();

        AccessTokenResponse tokenResponse = (AccessTokenResponse) token;
        assertThat(tokenResponse.getTokens().getAccessToken().getValue()).isEqualTo("TheAccessCode");
    }

    @Test
    public void getToken_withClientId_InvalidCredentials() {

        defineSecret(32);
        when(octopusServerConfigurationMock.getTokenEndpoint()).thenReturn("http://localhost:" + port() + "/oidc/token");
        when(octopusServerConfigurationMock.getSSOClientId()).thenReturn("JUnit_client");

        onRequest()
                .havingPathEqualTo("/oidc/token")
                .respond()
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withStatus(400)
                .withBody("{\"error_description\":\"ResourceOwnerPasswordCredentialsGrant is not allowed for client_id\",\"error\":\"unauthorized_client\"}\n");
        // Init uses the octopusCoreConfigurationMock, so that needs to be mocked first
        requestor = TokenRequestor.getInstance(octopusCoreConfigurationMock, octopusServerConfigurationMock);

        UsernamePasswordToken usernamePassword = new UsernamePasswordToken("JUnit", "SecretValue");
        TokenResponse token = requestor.getToken(usernamePassword);

        assertThat(token.indicatesSuccess()).isFalse();

    }

    private void defineSecret(int byteLength) {
        byte[] bytes = new byte[byteLength];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(bytes);

        when(octopusServerConfigurationMock.getSSOClientSecret()).thenReturn(bytes);

    }

    @Test
    public void getToken_NoSecret() {

        when(octopusServerConfigurationMock.getSSOClientSecret()).thenReturn(new byte[0]);
        when(octopusServerConfigurationMock.getTokenEndpoint()).thenReturn("http://localhost:" + port() + "/oidc/token");

        onRequest()
                .havingPathEqualTo("/oidc/token")
                .havingBody(new BodyMatcher(false))
                .respond()
                .withContentType(CommonContentTypes.APPLICATION_JSON.toString())
                .withBody("{\"token_type\":\"bearer\", \"access_token\":\"AnotherAccessCode\"}");
        // Init uses the octopusCoreConfigurationMock, so that needs to be mocked first
        requestor = TokenRequestor.getInstance(octopusCoreConfigurationMock, octopusServerConfigurationMock);

        UsernamePasswordToken usernamePassword = new UsernamePasswordToken("JUnit", "SecretValue");
        TokenResponse token = requestor.getToken(usernamePassword);

        assertThat(token.indicatesSuccess()).isTrue();

        AccessTokenResponse tokenResponse = (AccessTokenResponse) token;
        assertThat(tokenResponse.getTokens().getAccessToken().getValue()).isEqualTo("AnotherAccessCode");
    }

    private class BodyMatcher extends BaseMatcher<String> {

        private boolean hasClientAuth;

        private BodyMatcher(boolean hasClientAuth) {
            this.hasClientAuth = hasClientAuth;
        }

        @Override
        public boolean matches(Object item) {
            String body = item.toString();
            if (hasClientAuth) {
                return body.startsWith("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&password=SecretValue&grant_type=password&client_assertion=ey")
                        && body.endsWith("&username=JUnit");
            } else {
                return "password=SecretValue&grant_type=password&username=JUnit".equals(body);
            }
        }

        @Override
        public void describeTo(Description description) {

        }
    }

}