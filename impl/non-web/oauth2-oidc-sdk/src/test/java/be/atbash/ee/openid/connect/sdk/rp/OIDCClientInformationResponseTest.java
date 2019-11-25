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
package be.atbash.ee.openid.connect.sdk.rp;


import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import org.junit.Test;

import java.net.URI;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the OIDC client information response.
 */
public class OIDCClientInformationResponseTest {

    @Test
    public void testCycle()
            throws Exception {

        ClientID id = new ClientID("123");
        Date issueDate = new Date(new Date().getTime() / 1000 * 1000);
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setRedirectionURI(new URI("https://client.com/cb"));
        metadata.applyDefaults();
        Secret secret = new Secret();
        BearerAccessToken accessToken = new BearerAccessToken();
        URI uri = new URI("https://c2id.com/client-reg/123");

        OIDCClientInformation info = new OIDCClientInformation(
                id, issueDate, metadata, secret, uri, accessToken);

        OIDCClientInformationResponse response = new OIDCClientInformationResponse(info);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getOIDCClientInformation()).isEqualTo(info);
        assertThat(response.getClientInformation()).isEqualTo(info);

        HTTPResponse httpResponse = response.toHTTPResponse();

        response = OIDCClientInformationResponse.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getClientInformation().getID().getValue()).isEqualTo(id.getValue());
        assertThat(response.getClientInformation().getIDIssueDate()).isEqualTo(issueDate);
        assertThat(response.getClientInformation().getMetadata().getRedirectionURIs().iterator().next().toString()).isEqualTo("https://client.com/cb");
        assertThat(response.getClientInformation().getSecret().getValue()).isEqualTo(secret.getValue());
        assertThat(response.getClientInformation().getRegistrationURI().toString()).isEqualTo(uri.toString());
        assertThat(response.getClientInformation().getRegistrationAccessToken().getValue()).isEqualTo(accessToken.getValue());
    }
}
