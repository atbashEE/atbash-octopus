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
package be.atbash.ee.oauth2.sdk;



import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.Before;
import org.junit.Test;

import javax.json.JsonObject;
import java.net.URI;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests token error response serialisation and parsing.
 */
public class TokenErrorResponseTest  {
	
	
	private static URI ERROR_PAGE_URI = null;
	
	
	@Before
	public void setUp()
		throws Exception {
		
		ERROR_PAGE_URI = new URI("http://server.example.com/error/123");
	}

	@Test
	public void testStandardErrors() {
	
		Set<ErrorObject> errors = TokenErrorResponse.getStandardErrors();
	
		assertThat(errors).contains(OAuth2Error.INVALID_REQUEST);
		assertThat(errors).contains(OAuth2Error.INVALID_CLIENT);
		assertThat(errors).contains(OAuth2Error.INVALID_GRANT);
		assertThat(errors).contains(OAuth2Error.UNAUTHORIZED_CLIENT);
		assertThat(errors).contains(OAuth2Error.UNSUPPORTED_GRANT_TYPE);
		assertThat(errors).contains(OAuth2Error.INVALID_SCOPE);
		
		assertThat(errors).hasSize(6);
	}

	@Test
	public void testSerializeAndParse()
		throws Exception {
	
		ErrorObject err = OAuth2Error.INVALID_REQUEST.setURI(ERROR_PAGE_URI);

		TokenErrorResponse r = new TokenErrorResponse(err);

		assertThat(r.indicatesSuccess()).isFalse();
		assertThat(r.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
		

		HTTPResponse httpResponse = r.toHTTPResponse();
		
		assertThat(httpResponse.getStatusCode()).isEqualTo(HTTPResponse.SC_BAD_REQUEST);
		assertThat(httpResponse.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_JSON.toString());
		assertThat(httpResponse.getCacheControl()).isEqualTo("no-store");
		assertThat(httpResponse.getPragma()).isEqualTo("no-cache");
		
		
		JsonObject jsonObject = JSONObjectUtils.parse(httpResponse.getContent());

		assertThat(jsonObject.getString("error")).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
		assertThat(jsonObject.getString("error_description")).isEqualTo(OAuth2Error.INVALID_REQUEST.getDescription());
		assertThat(jsonObject.getString("error_uri")).isEqualTo(ERROR_PAGE_URI.toString());
		assertThat(jsonObject).hasSize(3);
		
		
		r = TokenErrorResponse.parse(httpResponse);

		assertThat(r.indicatesSuccess()).isFalse();
		assertThat(r.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
	}

	@Test
	public void testParseEmpty()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(404);

		TokenErrorResponse errorResponse = TokenErrorResponse.parse(httpResponse);

		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject().getHTTPStatusCode()).isEqualTo(404);
		assertThat(errorResponse.getErrorObject().getCode()).isNull();
		assertThat(errorResponse.getErrorObject().getDescription()).isNull();
		assertThat(errorResponse.getErrorObject().getURI()).isNull();
	}

	@Test
	public void testParseInvalidClient()
		throws Exception {

		HTTPResponse httpResponse = new HTTPResponse(401);
		httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
		httpResponse.setContent("{\"error\":\"invalid_client\", \"error_description\":\"Client authentication failed\"}");

		TokenErrorResponse errorResponse = TokenErrorResponse.parse(httpResponse);

		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_CLIENT.getCode());
		assertThat(errorResponse.getErrorObject().getDescription()).isEqualTo("Client authentication failed");
	}

	@Test
	public void testTokenErrorWithoutObject()
		throws Exception {

		TokenErrorResponse errorResponse = new TokenErrorResponse();
		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject()).isNull();
		assertThat(errorResponse.toJSONObject().isEmpty()).isTrue();

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();
		assertThat(httpResponse.getStatusCode()).isEqualTo(400);
		assertThat(httpResponse.getContentType()).isNull();
		assertThat(httpResponse.getContent()).isNull();

		errorResponse = TokenErrorResponse.parse(httpResponse);
		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject().getHTTPStatusCode()).isEqualTo(400);
		assertThat(errorResponse.getErrorObject().getCode()).isNull();
		assertThat(errorResponse.getErrorObject().getDescription()).isNull();
		assertThat(errorResponse.getErrorObject().getURI()).isNull();
		assertThat(errorResponse.toJSONObject().toString()).isEqualTo("{\"error\":null}"); // TODO
	}
}
