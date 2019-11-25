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



import be.atbash.ee.oauth2.sdk.pkce.CodeVerifier;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the authorisation code grant class.
 */
public class AuthorizationCodeGrantTest  {

@Test
	public void testConstructor()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode("abc");
		URI redirectURI = new URI("https://client.com/in");

		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, redirectURI);

		assertThat(grant.getAuthorizationCode()).isEqualTo(code);
		assertThat(grant.getRedirectionURI()).isEqualTo(redirectURI);

		assertThat(grant.getType()).isEqualTo(GrantType.AUTHORIZATION_CODE);

		Map<String, List<String>> params = grant.toParameters();
		assertThat(params.get("code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(params.get("redirect_uri")).isEqualTo(Collections.singletonList("https://client.com/in"));
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList("authorization_code"));
		assertThat(params).hasSize(3);

		grant = AuthorizationCodeGrant.parse(params);
		assertThat(grant.getAuthorizationCode()).isEqualTo(code);
		assertThat(grant.getRedirectionURI()).isEqualTo(redirectURI);
		assertThat(grant.getType()).isEqualTo(GrantType.AUTHORIZATION_CODE);
	}


	// PKCE
	@Test
	public void testConstructorWithCodeVerifier()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode("abc");
		URI redirectURI = new URI("https://client.com/in");
		CodeVerifier codeVerifier = new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, redirectURI, codeVerifier);

		assertThat(grant.getAuthorizationCode()).isEqualTo(code);
		assertThat(grant.getRedirectionURI()).isEqualTo(redirectURI);
		assertThat(grant.getCodeVerifier()).isEqualTo(codeVerifier);

		assertThat(grant.getType()).isEqualTo(GrantType.AUTHORIZATION_CODE);

		Map<String, List<String>> params = grant.toParameters();
		assertThat(params.get("code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(params.get("redirect_uri")).isEqualTo(Collections.singletonList("https://client.com/in"));
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList("authorization_code"));
		assertThat(params.get("code_verifier")).isEqualTo(Collections.singletonList(codeVerifier.getValue()));
		assertThat(params).hasSize(4);

		grant = AuthorizationCodeGrant.parse(params);
		assertThat(grant.getAuthorizationCode()).isEqualTo(code);
		assertThat(grant.getRedirectionURI()).isEqualTo(redirectURI);
		assertThat(grant.getType()).isEqualTo(GrantType.AUTHORIZATION_CODE);
		assertThat(grant.getCodeVerifier()).isEqualTo(codeVerifier);
	}

	@Test
	public void testConstructorWithoutRedirectionURI()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode("abc");

		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, null);

		assertThat(grant.getAuthorizationCode()).isEqualTo(code);
		assertThat(grant.getRedirectionURI()).isNull();

		assertThat(grant.getType()).isEqualTo(GrantType.AUTHORIZATION_CODE);

		Map<String, List<String>> params = grant.toParameters();
		assertThat(params.get("code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList("authorization_code"));
		assertThat(params).hasSize(2);

		grant = AuthorizationCodeGrant.parse(params);
		assertThat(grant.getAuthorizationCode()).isEqualTo(code);
		assertThat(grant.getRedirectionURI()).isNull();
		assertThat(grant.getType()).isEqualTo(GrantType.AUTHORIZATION_CODE);
	}

	@Test
	public void testParse()
		throws Exception {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("authorization_code"));
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));
		
		AuthorizationCodeGrant grant = AuthorizationCodeGrant.parse(params);
		
		assertThat(grant.getType()).isEqualTo(GrantType.AUTHORIZATION_CODE);
		assertThat(grant.getAuthorizationCode().getValue()).isEqualTo("abc");
		assertThat(grant.getRedirectionURI().toString()).isEqualTo("https://client.com/in");
	}

	@Test
	public void testParse_codeVerifierTooShort()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("authorization_code"));
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));
		params.put("code_verifier", Collections.singletonList("abc"));

		try {
			AuthorizationCodeGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("The code verifier must be at least 43 characters");
		}
	}

	@Test
	public void testParseMissingGrantType() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", null);
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));

		try {
			AuthorizationCodeGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"grant_type\" parameter");
			assertThat(e.getErrorObject().getURI()).isNull();
		}
	}

	@Test
	public void testParseUnsupportedGrant() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("no-such-grant"));
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));

		try {
			AuthorizationCodeGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Unsupported grant type: The \"grant_type\" must be \"authorization_code\"");
			assertThat(e.getErrorObject().getURI()).isNull();
		}
	}

	@Test
	public void testParseMissingCode() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("authorization_code"));
		params.put("code", Collections.singletonList(""));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));

		try {
			AuthorizationCodeGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing or empty \"code\" parameter");
			assertThat(e.getErrorObject().getURI()).isNull();
		}
	}

	@Test
	public void testParseInvalidRedirectionURI() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("authorization_code"));
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("invalid uri"));

		try {
			AuthorizationCodeGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Invalid \"redirect_uri\" parameter: Illegal character in path at index 7: invalid uri");
			assertThat(e.getErrorObject().getURI()).isNull();
			assertThat(e.getCause()).isInstanceOf(URISyntaxException.class);
		}
	}

	@Test
	public void testEquality() {

		assertThat(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), null)
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), null))).isTrue();

		assertThat(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb")))).isTrue();

		assertThat(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"), new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"), new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")))).isTrue();
	}

	@Test
	public void testInequality() {

		assertThat(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), null)
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("abc"), null))).isFalse();

		assertThat(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("abc"), URI.create("https://client.com/cb")))).isFalse();

		assertThat(new AuthorizationCodeGrant(new AuthorizationCode("abc"), URI.create("https://client.com/cb"), new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("abc"), URI.create("https://client.com/cb")))).isFalse();

		assertThat(new AuthorizationCodeGrant(new AuthorizationCode("abc"), URI.create("https://client.com/cb"), new CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("abc"), URI.create("https://client.com/cb"), new CodeVerifier("DBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")))).isFalse();

		assertThat(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), null))).isFalse();

		assertThat(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://client.com/cb"))
			.equals(new AuthorizationCodeGrant(new AuthorizationCode("xyz"), URI.create("https://other.com/cb")))).isFalse();
	}
}
