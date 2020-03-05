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
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the bearer access token class.
 */
public class BearerAccessTokenTest  {

	@Test
	public void testMinimalConstructor()
		throws Exception {
		
		AccessToken token = new BearerAccessToken("abc");
		
		assertThat(token.getValue()).isEqualTo("abc");
		assertThat(token.getLifetime()).isEqualTo(0l);
		assertThat(token.getScope()).isNull();
		
		assertThat(token.toAuthorizationHeader()).isEqualTo("Bearer abc");

		JsonObject json = token.toJSONObject();

		assertThat(json.getString("access_token")).isEqualTo("abc");
		assertThat(json.getString("token_type")).isEqualTo("Bearer");
		assertThat(json).hasSize(2);

		token = BearerAccessToken.parse(json);

		assertThat(token.getValue()).isEqualTo("abc");
		assertThat(token.getLifetime()).isEqualTo(0l);
		assertThat(token.getScope()).isNull();

		assertThat(token.getParameterNames()).contains("access_token");
		assertThat(token.getParameterNames()).contains("token_type");
		assertThat(token.getParameterNames()).hasSize(2);
	}

	@Test
	public void testGenerate() {

		AccessToken token = new BearerAccessToken(12);

		assertThat(token).isNotNull();

		assertThat(new Base64URLValue(token.getValue()).decode().length).isEqualTo(12);
		assertThat(token.getLifetime()).isEqualTo(0l);
		assertThat(token.getScope()).isNull();

		String header = token.toAuthorizationHeader();
		assertThat(header.startsWith("Bearer ")).isTrue();
		assertThat(header.substring("Bearer ".length())).isEqualTo(token.getValue());
	}

	@Test
	public void testGenerateDefault() {

		AccessToken token = new BearerAccessToken();

		assertThat(token).isNotNull();

		assertThat(new Base64URLValue(token.getValue()).decode().length).isEqualTo(32);
		assertThat(token.getLifetime()).isEqualTo(0l);
		assertThat(token.getScope()).isNull();

		String header = token.toAuthorizationHeader();
		assertThat(header.startsWith("Bearer ")).isTrue();
		assertThat(header.substring("Bearer ".length())).isEqualTo(token.getValue());
	}

	@Test
	public void testFullConstructor()
		throws Exception {
		
		Scope scope = Scope.parse("read write");

		AccessToken token = new BearerAccessToken("abc", 1500, scope);
		
		assertThat(token.getValue()).isEqualTo("abc");
		assertThat(token.getLifetime()).isEqualTo(1500L);
		assertThat(token.getScope().containsAll(Scope.parse("read write"))).isTrue();
		
		assertThat(token.toAuthorizationHeader()).isEqualTo("Bearer abc");

		JsonObject json = token.toJSONObject();

		assertThat(json.getString("access_token")).isEqualTo("abc");
		assertThat(json.getString("token_type")).isEqualTo("Bearer");
		assertThat(json.getJsonNumber("expires_in").longValue()).isEqualTo(1500L);
		assertThat(Scope.parse(json.getString("scope")).equals(scope)).isTrue();
		assertThat(json).hasSize(4);

		token = BearerAccessToken.parse(json);

		assertThat(json.getString("access_token")).isEqualTo("abc");
		assertThat(json.getString("token_type")).isEqualTo("Bearer");
		assertThat(json.getJsonNumber("expires_in").longValue()).isEqualTo(1500L);
		assertThat(Scope.parse(json.getString("scope")).equals(scope)).isTrue();
		assertThat(json).hasSize(4);

		assertThat(token.getParameterNames()).contains("access_token");
		assertThat(token.getParameterNames()).contains("token_type");
		assertThat(token.getParameterNames()).contains("expires_in");
		assertThat(token.getParameterNames()).contains("scope");
		assertThat(token.getParameterNames()).hasSize(4);
	}

	@Test
	public void testParseFromHeader()
		throws Exception {
	
		AccessToken token = AccessToken.parse("Bearer abc");
		
		assertThat(token.getValue()).isEqualTo("abc");
		assertThat(token.getLifetime()).isEqualTo(0l);
		assertThat(token.getScope()).isNull();

		assertThat(token.getParameterNames()).contains("access_token");
		assertThat(token.getParameterNames()).contains("token_type");
		assertThat(token.getParameterNames()).hasSize(2);
	}

	@Test
	public void testParseFromHeader_missing() {

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                AccessToken.parse((String) null));

        assertThat(exception.getErrorObject().getHTTPStatusCode()).isEqualTo(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode());
        assertThat(exception.getErrorObject().getCode()).isEqualTo(BearerTokenError.MISSING_TOKEN.getCode());

    }

	@Test
	public void testParseFromHeader_missingName() {

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> AccessToken.parse("abc"));

        assertThat(exception.getErrorObject().getHTTPStatusCode()).isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
        assertThat(exception.getErrorObject().getCode()).isEqualTo(BearerTokenError.INVALID_REQUEST.getCode());

    }

	@Test
	public void testParseFromHeader_missingValue() {

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> AccessToken.parse("Bearer "));

        assertThat(exception.getErrorObject().getHTTPStatusCode()).isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
        assertThat(exception.getErrorObject().getCode()).isEqualTo(BearerTokenError.INVALID_REQUEST.getCode());
    }

    @Test
    public void testParseFromQueryParameters()
            throws Exception {

        Map<String, List<String>> params = new HashMap<>();
        params.put("access_token", Collections.singletonList("abc"));

        assertThat(BearerAccessToken.parse(params).getValue()).isEqualTo("abc");
    }

	@Test
	public void testParseFromQueryParameters_missing() {

        Map<String, List<String>> params = new HashMap<>();
        params.put("some_param", Collections.singletonList("abc"));

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> BearerAccessToken.parse(params));

        assertThat(exception.getMessage()).isEqualTo("Missing access token parameter");
        assertThat(exception.getErrorObject().getHTTPStatusCode()).isEqualTo(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode());
        assertThat(exception.getErrorObject().getCode()).isEqualTo(BearerTokenError.MISSING_TOKEN.getCode());

    }

	@Test
	public void testParseFromQueryParameters_empty() {

        Map<String, List<String>> params = new HashMap<>();
        params.put("access_token", Collections.singletonList(""));

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> BearerAccessToken.parse(params));

        assertThat(exception.getMessage()).isEqualTo("Blank / empty access token");
        assertThat(exception.getErrorObject().getHTTPStatusCode()).isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
        assertThat(exception.getErrorObject().getCode()).isEqualTo(BearerTokenError.INVALID_REQUEST.getCode());
    }

    @Test
    public void testParseFromHTTPRequest()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://c2id.com/reg/123"));
        httpRequest.setAuthorization("Bearer abc");

        BearerAccessToken accessToken = BearerAccessToken.parse(httpRequest);

        assertThat(accessToken.getValue()).isEqualTo("abc");
    }

	@Test
	public void testParseFromHTTPRequest_missing()
		throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://c2id.com/reg/123"));

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> BearerAccessToken.parse(httpRequest));

        assertThat(exception.getErrorObject().getHTTPStatusCode()).isEqualTo(401);
        assertThat(exception.getErrorObject().getCode()).isNull();
    }

	@Test
	public void testParseFromHTTPRequest_invalid()
		throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://c2id.com/reg/123"));
        httpRequest.setAuthorization("Bearer");

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> BearerAccessToken.parse(httpRequest));

        assertThat(exception.getErrorObject().getHTTPStatusCode()).isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
        assertThat(exception.getErrorObject().getCode()).isEqualTo(BearerTokenError.INVALID_REQUEST.getCode());
    }

	@Test
	public void testParseException_validChars_TokenTypeMustBeBearer() {

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add("token_type", "some-token-type");

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> BearerAccessToken.parse(jsonObject.build()));

        assertThat(exception.getMessage()).isEqualTo("Token type must be Bearer");

        assertThat(BearerTokenError.isDescriptionWithValidChars(exception.getMessage())).isTrue();
    }

	@Test
	public void testParseExpiresInError() {

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add("token_type", "Bearer");
        jsonObject.add("access_token", "xyz");
        jsonObject.add("expires_in", "invalid-time");

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> BearerAccessToken.parse(jsonObject.build()));

        assertThat(exception.getMessage()).isEqualTo("Invalid expires_in parameter, must be integer");

        assertThat(BearerTokenError.isDescriptionWithValidChars(exception.getMessage())).isTrue();

    }


    // https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/276/bearer-access-token-invalid-error-message
	@Test
	public void testParseHeader_tokenTypeMustBeBearer() {

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () -> BearerAccessToken.parse("XYZ aiXe4moo8aiguaL4ohnu3bod"));

        assertThat(exception.getMessage()).isEqualTo("Token type must be Bearer");
        assertThat(BearerTokenError.isDescriptionWithValidChars(exception.getMessage())).isTrue();
    }
}
