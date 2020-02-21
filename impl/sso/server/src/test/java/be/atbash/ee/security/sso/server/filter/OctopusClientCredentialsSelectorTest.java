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
package be.atbash.ee.security.sso.server.filter;

import be.atbash.ee.oauth2.sdk.auth.ClientSecretJWT;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.auth.verifier.ClientAuthenticationVerifier;
import be.atbash.ee.oauth2.sdk.auth.verifier.InvalidClientException;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.client.ClientInfoRetriever;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class OctopusClientCredentialsSelectorTest {

    @Mock
    private ClientInfoRetriever clientInfoRetrieverMock;

    @InjectMocks
    private OctopusClientCredentialsSelector credentialsSelector;

    private String clientSecretBase64Encoded = "szxK-5_eJjs-aUj-64MpUZ-GPPzGLhYPLGl0wrYjYNVAGva2P0lLe6UGKGM7k8dWxsOVGutZWgvmY3l5oVPO3w";

    @Test
    public void selectClientSecrets() throws  InvalidClientException, URISyntaxException {

        Secret secret = new Secret(new Base64URLValue(clientSecretBase64Encoded));

        ClientID clientId = new ClientID("junit_client");
        ClientSecretJWT clientAuthentication = new ClientSecretJWT(clientId, new URI("http://some.server/oidc"), JWSAlgorithm.HS256, secret);

        Set<Audience> expectedAudience = new HashSet<>();
        expectedAudience.add(new Audience("http://some.server/oidc"));  // Audience must the the endpoint
        ClientAuthenticationVerifier<Object> authenticationVerifier = new ClientAuthenticationVerifier<>(credentialsSelector, null, expectedAudience);

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setClientSecret(clientSecretBase64Encoded);
        when(clientInfoRetrieverMock.retrieveInfo(clientId.getValue())).thenReturn(clientInfo);

        authenticationVerifier.verify(clientAuthentication, null, null);

    }

}