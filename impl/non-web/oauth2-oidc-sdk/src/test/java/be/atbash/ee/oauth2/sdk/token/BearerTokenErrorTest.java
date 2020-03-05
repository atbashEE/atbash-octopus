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
package be.atbash.ee.oauth2.sdk.token;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.Scope;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;


public class BearerTokenErrorTest {

	@Test
	public void testConstantCodes() {

		assertThat(BearerTokenError.MISSING_TOKEN.getCode()).isNull();
		assertThat(BearerTokenError.INVALID_REQUEST.getCode()).isEqualTo("invalid_request");
		assertThat(BearerTokenError.INVALID_TOKEN.getCode()).isEqualTo("invalid_token");
		assertThat(BearerTokenError.INSUFFICIENT_SCOPE.getCode()).isEqualTo("insufficient_scope");
	}

	@Test
	public void testSerializeAndParseWWWAuthHeader()
		throws Exception {

		BearerTokenError error = BearerTokenError.INVALID_TOKEN.setRealm("example.com");

		assertThat(error.getRealm()).isEqualTo("example.com");
		assertThat(error.getCode()).isEqualTo("invalid_token");

		String wwwAuth = error.toWWWAuthenticateHeader();

		error = BearerTokenError.parse(wwwAuth);

		assertThat(error.getRealm()).isEqualTo("example.com");
		assertThat(error.getCode()).isEqualTo("invalid_token");
	}

	@Test
	public void testNullRealm() {

		BearerTokenError error = BearerTokenError.INVALID_REQUEST.setRealm(null);

		assertThat(error.getRealm()).isNull();
	}

	@Test
	public void testNoErrorCode()
		throws Exception {

		String wwwAuth = "Bearer realm=\"example.com\"";

		BearerTokenError error = BearerTokenError.parse(wwwAuth);

		assertThat(BearerTokenError.MISSING_TOKEN).isEqualTo(error);

		assertThat(error.getRealm()).isEqualTo("example.com");
		assertThat(error.getCode()).isNull();
	}

	@Test
	public void testInsufficientScope()
		throws Exception {

		BearerTokenError error = BearerTokenError.INSUFFICIENT_SCOPE;
		error = error.setScope(Scope.parse("offline_access"));

		String wwwAuth = error.toWWWAuthenticateHeader();

		error = BearerTokenError.parse(wwwAuth);

		assertThat(error.getScope()).isEqualTo(Scope.parse("offline_access"));
	}

	@Test
	public void testSetDescription() {

		assertThat(BearerTokenError.INSUFFICIENT_SCOPE.setDescription("description").getDescription()).isEqualTo("description");
	}

	@Test
	public void testAppendDescription() {

		assertThat(BearerTokenError.INSUFFICIENT_SCOPE.appendDescription(": offline_access").getDescription()).isEqualTo("Insufficient scope: offline_access");
	}

	@Test
	public void testSetHTTPStatusCode() {

		assertThat(BearerTokenError.INSUFFICIENT_SCOPE.setHTTPStatusCode(400).getHTTPStatusCode()).isEqualTo(400);
	}

	@Test
	public void testSetURI()
		throws Exception {

		URI uri = new URI("http://example.com");

		assertThat(BearerTokenError.INSUFFICIENT_SCOPE.setURI(uri).getURI()).isEqualTo(uri);
	}

	@Test
	public void testParseInvalidTokenHeader()
		throws Exception {

		String header = "Bearer error=\"invalid_token\", error_description=\"Invalid access token\"";

		BearerTokenError error = BearerTokenError.parse(header);

		assertThat(error).isEqualTo(BearerTokenError.INVALID_TOKEN);
		assertThat(error.getDescription()).isEqualTo("Invalid access token");
		assertThat(error.getURI()).isNull();
		assertThat(error.getRealm()).isNull();
	}
	
	
	// see https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/197/userinfo-error-response-by-google-not
	@Test
	public void testParseGoogleBearerTokenError()
		throws Exception {
		
		String header = "Bearer realm=\"https://acounts.google.com/\", error=invalid_token";
		
		BearerTokenError error = BearerTokenError.parse(header);
		assertThat(error).isEqualTo(BearerTokenError.INVALID_TOKEN);
		assertThat(error.getCode()).isEqualTo("invalid_token");
		assertThat(error.getDescription()).isNull();
		assertThat(error.getURI()).isNull();
		assertThat(error.getRealm()).isEqualTo("https://acounts.google.com/");
	}
	
	
	// see https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/197/userinfo-error-response-by-google-not
	@Test
	public void testParseGoogleBearerTokenError_extended()
		throws Exception {
		
		String header = "Bearer realm=\"https://acounts.google.com/\", error=invalid_token, error_description=\"Invalid access token\"";
		
		BearerTokenError error = BearerTokenError.parse(header);
		assertThat(error).isEqualTo(BearerTokenError.INVALID_TOKEN);
		assertThat(error.getCode()).isEqualTo("invalid_token");
		assertThat(error.getDescription()).isEqualTo("Invalid access token");
		assertThat(error.getURI()).isNull();
		assertThat(error.getRealm()).isEqualTo("https://acounts.google.com/");
	}

	@Test
	public void testRealmWithEscapeDoubleQuotes()
		throws Exception {
		
		BearerTokenError error = BearerTokenError.INVALID_TOKEN.setRealm("\"my-realm\"");
		
		assertThat(error.getRealm()).isEqualTo("\"my-realm\"");
		
		String wwwAuthHeader = error.toWWWAuthenticateHeader();
		
		assertThat(wwwAuthHeader).isEqualTo("Bearer realm=\"\\\"my-realm\\\"\", error=\"invalid_token\", error_description=\"Invalid access token\"");
		
		BearerTokenError parsed = BearerTokenError.parse(wwwAuthHeader);
		
		assertThat(parsed.getRealm()).isEqualTo(error.getRealm());
	}

	@Test
	public void testInvalidCharsInErrorCode() {

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                new BearerTokenError("\"invalid_token\"", null));

        assertThat(exception.getMessage()).isEqualTo("The error code contains invalid ASCII characters, see RFC 6750, section 3");

    }

	@Test
	public void testInvalidCharsInErrorDescription() {

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                new BearerTokenError("invalid_token", "Invalid token: \"abc\""));
        assertThat(exception.getMessage()).isEqualTo("The error description contains invalid ASCII characters, see RFC 6750, section 3");
    }

	@Test
	public void testInvalidCharsInScope() {

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> BearerTokenError.INSUFFICIENT_SCOPE.setScope(new Scope("read", "\"write\"")));
        assertThat(exception.getMessage()).isEqualTo("The scope contains invalid ASCII characters, see RFC 6750, section 3");

    }

	@Test
	public void testParseWWWAuthenticateHeader_invalidCharsInErrorCode()
		throws OAuth2JSONParseException {
		
		// skip invalid error code
		assertThat(BearerTokenError.parse("Bearer error=\"\"invalid token\"").getCode()).isNull();
	}

	@Test
	public void testIgnoreParseInvalidErrorURI()
		throws OAuth2JSONParseException {
		
		BearerTokenError error = BearerTokenError.parse("Bearer error=invalid_token, error_uri=\"a b c\"");
		
		assertThat(error.getCode()).isEqualTo(BearerTokenError.INVALID_TOKEN.getCode());
		assertThat(error.getURI()).isNull();
	}
}
