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
package be.atbash.ee.openid.connect.sdk.rp;


import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the OIDC client update request.
 */
public class OIDCClientUpdateRequestTest {

    @Test
    public void testCycle()
            throws Exception {

        URI uri = new URI("https://c2id.com/client-reg/123");
        ClientID clientID = new ClientID("123");
        BearerAccessToken accessToken = new BearerAccessToken();
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setRedirectionURI(new URI("https://client.com/cb"));
        metadata.setName("My app");
        metadata.applyDefaults();
        Secret secret = new Secret();

        OIDCClientUpdateRequest request = new OIDCClientUpdateRequest(
                uri,
                clientID,
                accessToken,
                metadata,
                secret);

        assertThat(request.getEndpointURI()).isEqualTo(uri);
        assertThat(request.getClientID()).isEqualTo(clientID);
        assertThat(request.getAccessToken()).isEqualTo(accessToken);
        assertThat(request.getOIDCClientMetadata()).isEqualTo(metadata);
        assertThat(request.getClientMetadata()).isEqualTo(metadata);
        assertThat(request.getClientSecret()).isEqualTo(secret);


        HTTPRequest httpRequest = request.toHTTPRequest();

        request = OIDCClientUpdateRequest.parse(httpRequest);

        assertThat(request.getEndpointURI().toString()).isEqualTo(uri.toString());
        assertThat(request.getClientID().getValue()).isEqualTo(clientID.getValue());
        assertThat(request.getAccessToken().getValue()).isEqualTo(accessToken.getValue());
        assertThat(request.getClientMetadata().getRedirectionURIs().iterator().next().toString()).isEqualTo("https://client.com/cb");
        assertThat(request.getClientMetadata().getName()).isEqualTo("My app");
        assertThat(request.getClientSecret().getValue()).isEqualTo(secret.getValue());
    }
}
