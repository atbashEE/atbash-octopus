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


import be.atbash.ee.oauth2.sdk.client.ClientRegistrationErrorResponse;
import be.atbash.ee.oauth2.sdk.client.ClientRegistrationResponse;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.oauth2.sdk.token.BearerTokenError;
import org.junit.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the OIDC client registration response parser.
 */
public class OIDCClientRegistrationResponseParserTest {

    @Test
    public void testParseSuccess()
            throws Exception {

        ClientID id = new ClientID("123");
        OIDCClientMetadata metadata = new OIDCClientMetadata();
        metadata.setRedirectionURI(new URI("https://client.com/cb"));
        URI regURI = new URI("https://c2id.com/client-reg/123");
        BearerAccessToken accessToken = new BearerAccessToken();
        metadata.setName("My app");
        metadata.applyDefaults();

        OIDCClientInformation clientInfo = new OIDCClientInformation(id, null, metadata, null, regURI, accessToken);

        OIDCClientInformationResponse response = new OIDCClientInformationResponse(clientInfo);

        assertThat(response.indicatesSuccess()).isTrue();

        HTTPResponse httpResponse = response.toHTTPResponse();

        ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

        assertThat(regResponse.indicatesSuccess()).isTrue();
        response = (OIDCClientInformationResponse) regResponse;

        assertThat(response.getOIDCClientInformation().getID()).isEqualTo(id);
        assertThat(response.getOIDCClientInformation().getMetadata().getName()).isEqualTo("My app");
        assertThat(response.getOIDCClientInformation().getSecret()).isNull();
        assertThat(response.getOIDCClientInformation().getIDIssueDate()).isNull();
        assertThat(response.getOIDCClientInformation().getRegistrationURI()).isEqualTo(regURI);
        assertThat(response.getOIDCClientInformation().getRegistrationAccessToken().getValue()).isEqualTo(accessToken.getValue());
    }

    @Test
    public void testParseError()
            throws Exception {

        ClientRegistrationErrorResponse response = new ClientRegistrationErrorResponse(BearerTokenError.INVALID_TOKEN);
        assertThat(response.indicatesSuccess()).isFalse();

        HTTPResponse httpResponse = response.toHTTPResponse();

        ClientRegistrationResponse regResponse = OIDCClientRegistrationResponseParser.parse(httpResponse);

        assertThat(regResponse.indicatesSuccess()).isFalse();
        response = (ClientRegistrationErrorResponse) regResponse;
        assertThat(response.getErrorObject().getCode()).isEqualTo(BearerTokenError.INVALID_TOKEN.getCode());
    }
}
