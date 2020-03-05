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


import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.BearerTokenError;
import org.junit.jupiter.api.Test;

import javax.json.JsonObject;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the client registration error response class.
 */
public class ClientRegistrationErrorResponseTest  {

	@Test
	public void testStdErrors() {

		assertThat(ClientRegistrationErrorResponse.getStandardErrors()).contains(BearerTokenError.MISSING_TOKEN);
		assertThat(ClientRegistrationErrorResponse.getStandardErrors()).contains(BearerTokenError.INVALID_REQUEST);
		assertThat(ClientRegistrationErrorResponse.getStandardErrors()).contains(BearerTokenError.INVALID_TOKEN);
		assertThat(ClientRegistrationErrorResponse.getStandardErrors()).contains(BearerTokenError.INSUFFICIENT_SCOPE);
		assertThat(ClientRegistrationErrorResponse.getStandardErrors()).contains(RegistrationError.INVALID_REDIRECT_URI);
		assertThat(ClientRegistrationErrorResponse.getStandardErrors()).contains(RegistrationError.INVALID_CLIENT_METADATA);
		assertThat(ClientRegistrationErrorResponse.getStandardErrors()).contains(RegistrationError.INVALID_SOFTWARE_STATEMENT);
		assertThat(ClientRegistrationErrorResponse.getStandardErrors()).contains(RegistrationError.UNAPPROVED_SOFTWARE_STATEMENT);

		assertThat(ClientRegistrationErrorResponse.getStandardErrors()).hasSize(8);
	}

	@Test
	public void testErrorObject() {

		ClientRegistrationErrorResponse errorResponse =
			new ClientRegistrationErrorResponse(RegistrationError.INVALID_REDIRECT_URI);

		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject()).isEqualTo(RegistrationError.INVALID_REDIRECT_URI);
	}

	@Test
	public void testToHTTPResponse()
		throws Exception {

		HTTPResponse httpResponse =
			new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA).toHTTPResponse();

		assertThat(httpResponse.getStatusCode()).isEqualTo(400);
		assertThat(CommonContentTypes.APPLICATION_JSON.match(httpResponse.getContentType())).isTrue();
		JsonObject content = httpResponse.getContentAsJSONObject();
		assertThat(content.getString("error")).isEqualTo("invalid_client_metadata");
		assertThat(content.getString("error_description")).isEqualTo("Invalid client metadata field");

		assertThat(httpResponse.getCacheControl()).isEqualTo("no-store");
		assertThat(httpResponse.getPragma()).isEqualTo("no-cache");
	}

	@Test
	public void testParse()
		throws Exception {

		HTTPResponse httpResponse =
			new ClientRegistrationErrorResponse(RegistrationError.INVALID_CLIENT_METADATA).toHTTPResponse();

		ClientRegistrationErrorResponse errorResponse =
			ClientRegistrationErrorResponse.parse(httpResponse);

		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject()).isEqualTo(RegistrationError.INVALID_CLIENT_METADATA);
	}

	@Test
	public void testParse404NotFound()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(404);

		ClientRegistrationErrorResponse errorResponse =
			ClientRegistrationErrorResponse.parse(httpResponse);

		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject().toJSONObject().isEmpty()).isTrue();
	}
}
