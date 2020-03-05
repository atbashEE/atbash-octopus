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
package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.oauth2.sdk.token.BearerTokenError;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URL;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the client read request.
 */
public class ClientReadRequestTest  {

	@Test
	public void testCycle()
		throws Exception {

		URI uri = new URI("https://c2id.com/client-reg/123");
		BearerAccessToken accessToken = new BearerAccessToken();

		ClientReadRequest request = new ClientReadRequest(uri, accessToken);

		assertThat(request.getEndpointURI()).isEqualTo(uri);
		assertThat(request.getAccessToken()).isEqualTo(accessToken);

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.GET);
		assertThat(httpRequest.getURL().toURI()).isEqualTo(uri);
		assertThat(httpRequest.getAuthorization()).isEqualTo(accessToken.toAuthorizationHeader());

		request = ClientReadRequest.parse(httpRequest);

		assertThat(request.getEndpointURI().toString()).isEqualTo(uri.toString());
		assertThat(request.getAccessToken().getValue()).isEqualTo(accessToken.getValue());
	}

	@Test
	public void testParseWithMissingAuthorizationHeader()
		throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/client-reg/123"));

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> ClientReadRequest.parse(httpRequest));

        assertThat(exception.getErrorObject()).isInstanceOf(BearerTokenError.class);

        BearerTokenError bte = (BearerTokenError) exception.getErrorObject();

        assertThat(bte.getHTTPStatusCode()).isEqualTo(401);
        assertThat(bte.getCode()).isNull();
        assertThat(bte.toWWWAuthenticateHeader()).isEqualTo("Bearer");

    }
}
