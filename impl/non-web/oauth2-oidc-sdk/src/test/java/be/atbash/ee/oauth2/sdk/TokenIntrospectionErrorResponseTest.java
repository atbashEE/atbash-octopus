/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package be.atbash.ee.oauth2.sdk;


import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.BearerTokenError;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the token introspection error class.
 */
public class TokenIntrospectionErrorResponseTest{
	
	@Test
	public void testStdErrors() {

		assertThat(TokenIntrospectionErrorResponse.getStandardErrors()).contains(OAuth2Error.INVALID_REQUEST);
		assertThat(TokenIntrospectionErrorResponse.getStandardErrors()).contains(OAuth2Error.INVALID_CLIENT);

		assertThat(TokenIntrospectionErrorResponse.getStandardErrors()).contains(BearerTokenError.MISSING_TOKEN);
		assertThat(TokenIntrospectionErrorResponse.getStandardErrors()).contains(BearerTokenError.INVALID_REQUEST);
		assertThat(TokenIntrospectionErrorResponse.getStandardErrors()).contains(BearerTokenError.INVALID_TOKEN);
		assertThat(TokenIntrospectionErrorResponse.getStandardErrors()).contains(BearerTokenError.INSUFFICIENT_SCOPE);

		assertThat(TokenIntrospectionErrorResponse.getStandardErrors()).hasSize(5);
	}

	@Test
	public void testNoErrorObject() {

		TokenIntrospectionErrorResponse errorResponse = new TokenIntrospectionErrorResponse(null);
		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject()).isNull();
		HTTPResponse httpResponse = errorResponse.toHTTPResponse();
		assertThat(httpResponse.getStatusCode()).isEqualTo(400);
		assertThat(httpResponse.getContentType()).isNull();
		assertThat(httpResponse.getContent()).isNull();
	}

	@Test
	public void testInvalidClientAuth()
		throws OAuth2JSONParseException {

		TokenIntrospectionErrorResponse errorResponse = new TokenIntrospectionErrorResponse(OAuth2Error.INVALID_CLIENT);
		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject()).isEqualTo(OAuth2Error.INVALID_CLIENT);

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		assertThat(httpResponse.getStatusCode()).isEqualTo(401);
		assertThat(CommonContentTypes.APPLICATION_JSON.match(httpResponse.getContentType())).isTrue();
		assertThat(OAuth2Error.INVALID_CLIENT.getCode().equals(ErrorObject.parse(httpResponse.getContentAsJSONObject()).getCode())).isTrue();
		assertThat(OAuth2Error.INVALID_CLIENT.getDescription().equals(ErrorObject.parse(httpResponse.getContentAsJSONObject()).getDescription())).isTrue();

		errorResponse = TokenIntrospectionErrorResponse.parse(httpResponse);

		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject()).isEqualTo(OAuth2Error.INVALID_CLIENT);
	}

	@Test
	public void testInvalidClientAuthz()
		throws OAuth2JSONParseException {

		TokenIntrospectionErrorResponse errorResponse = new TokenIntrospectionErrorResponse(BearerTokenError.INVALID_TOKEN);
		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject()).isEqualTo(BearerTokenError.INVALID_TOKEN);

		HTTPResponse httpResponse = errorResponse.toHTTPResponse();

		assertThat(httpResponse.getStatusCode()).isEqualTo(401);
		assertThat(httpResponse.getWWWAuthenticate()).isEqualTo(BearerTokenError.INVALID_TOKEN.toWWWAuthenticateHeader());
		assertThat(CommonContentTypes.APPLICATION_JSON.match(httpResponse.getContentType())).isTrue();
		assertThat(BearerTokenError.INVALID_TOKEN.getCode().equals(ErrorObject.parse(httpResponse.getContentAsJSONObject()).getCode())).isTrue();
		assertThat(BearerTokenError.INVALID_TOKEN.getDescription().equals(ErrorObject.parse(httpResponse.getContentAsJSONObject()).getDescription())).isTrue();

		errorResponse = TokenIntrospectionErrorResponse.parse(httpResponse);

		assertThat(errorResponse.indicatesSuccess()).isFalse();
		assertThat(errorResponse.getErrorObject()).isEqualTo(BearerTokenError.INVALID_TOKEN);
	}
}
