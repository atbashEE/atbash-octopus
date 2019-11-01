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
package be.atbash.ee.security.octopus.keycloak.filter.authc;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.authc.CredentialsException;
import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParameters;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keycloak.adapter.KeycloakUserToken;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SecretKeyType;
import be.atbash.ee.security.octopus.keys.selector.filter.SecretKeyTypeKeyFilter;
import be.atbash.ee.security.octopus.nimbus.jose.jwk.KeyType;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolVersion;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.message.BasicStatusLine;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;
import org.keycloak.util.JsonSerialization;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class KeycloakAuthenticatingFilterTest {

    @Mock
    private KeycloakDeployment keycloakDeploymentMock;

    @Mock
    private HttpClient httpClientMock;

    @InjectMocks
    private KeycloakAuthenticatingFilter filter;

    @Captor
    private ArgumentCaptor<HttpGet> httpGetCaptor;

    @Test
    public void createToken() throws IOException {
        when(keycloakDeploymentMock.getAccountUrl()).thenReturn("localhost:8080/auth/realms/demo/protocol/openid-connect/account");
        when(keycloakDeploymentMock.getClient()).thenReturn(httpClientMock);

        StatusLine statusLine = new BasicStatusLine(new ProtocolVersion("http", 1, 1), 200, "xx");
        HttpResponse httpResponse = new BasicHttpResponse(statusLine);
        IDToken idToken = new IDToken();
        idToken.setFamilyName("Atbash");
        StringEntity entity = new StringEntity(JsonSerialization.writeValueAsString(idToken));

        httpResponse.setEntity(entity);
        when(httpClientMock.execute(any(HttpGet.class))).thenReturn(httpResponse);

        String token = createAccessToken();
        AuthenticationToken authenticationToken = filter.createToken(null, token);

        assertThat(authenticationToken).isInstanceOf(KeycloakUserToken.class);

        KeycloakUserToken keycloakUserToken = (KeycloakUserToken) authenticationToken;
        assertThat(keycloakUserToken.getAccessToken()).isEqualTo(token);
        assertThat(keycloakUserToken.getLastName()).isEqualTo("Atbash");
        assertThat(keycloakUserToken.getRoles()).containsOnly("role1", "role2");

        verify(httpClientMock).execute(httpGetCaptor.capture());
        assertThat(httpGetCaptor.getValue().getURI().toString()).isEqualTo("localhost:8080/auth/realms/demo/protocol/openid-connect/protocol/openid-connect/userinfo");
        assertThat(httpGetCaptor.getValue().getFirstHeader(OctopusConstants.AUTHORIZATION_HEADER).getValue()).isEqualTo("Bearer " + token);
    }

    @Test(expected = CredentialsException.class)
    public void createToke_invalidAuthorization() throws IOException {
        when(keycloakDeploymentMock.getAccountUrl()).thenReturn("localhost:8080/auth/realms/demo/protocol/openid-connect/account");
        when(keycloakDeploymentMock.getClient()).thenReturn(httpClientMock);

        StatusLine statusLine = new BasicStatusLine(new ProtocolVersion("http", 1, 1), 400, "Not Found");
        HttpResponse httpResponse = new BasicHttpResponse(statusLine);
        IDToken idToken = new IDToken();
        idToken.setFamilyName("Atbash");
        StringEntity entity = new StringEntity(JsonSerialization.writeValueAsString(idToken));

        httpResponse.setEntity(entity);
        when(httpClientMock.execute(any(HttpGet.class))).thenReturn(httpResponse);

        try {
            filter.createToken(null, "doesn't matter here in this test");
        } finally {

            verify(httpClientMock).execute(any(HttpGet.class));
        }
    }

    @Test(expected = CredentialsException.class)
    public void createToke_ioException() throws IOException {
        when(keycloakDeploymentMock.getAccountUrl()).thenReturn("localhost:8080/auth/realms/demo/protocol/openid-connect/account");
        when(keycloakDeploymentMock.getClient()).thenReturn(httpClientMock);

        when(httpClientMock.execute(any(HttpGet.class))).thenThrow(new IOException("Server not found"));

        try {
            filter.createToken(null, "doesn't matter here in this test");
        } finally {

            verify(httpClientMock).execute(any(HttpGet.class));
        }
    }

    private String createAccessToken() {
        AccessToken accessToken = new AccessToken();
        AccessToken.Access access = new AccessToken.Access();
        access.addRole("role1");
        access.addRole("role2");
        accessToken.setRealmAccess(access);
        JWTEncoder jwtEncoder = new JWTEncoder();

        // generate RSA keys.
        List<AtbashKey> atbashKeys = defineRSAKey();

        // create JWT for AccessToken
        AtbashKey atbashKey = getPrivateKey(atbashKeys);

        JWTParameters parameters = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS)
                .withSecretKeyForSigning(atbashKey)
                .build();

        return jwtEncoder.encode(accessToken, parameters);
    }

    private List<AtbashKey> defineRSAKey() {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("Test")
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

    private AtbashKey getPrivateKey(List<AtbashKey> atbashKeys) {
        List<AtbashKey> keys = new SecretKeyTypeKeyFilter(new SecretKeyType(KeyType.RSA, AsymmetricPart.PRIVATE)).filter(atbashKeys);
        if (keys.size() != 1) {
            throw new AtbashUnexpectedException("Could not find the RSA Private key");
        }
        return keys.get(0);
    }

}