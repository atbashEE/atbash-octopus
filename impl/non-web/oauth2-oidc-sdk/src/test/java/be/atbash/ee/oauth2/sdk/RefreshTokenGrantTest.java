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


import be.atbash.ee.oauth2.sdk.token.RefreshToken;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the refresh token grant.
 */
public class RefreshTokenGrantTest  {

	@Test
	public void testConstructor() {

		RefreshToken refreshToken = new RefreshToken();
		RefreshTokenGrant grant = new RefreshTokenGrant(refreshToken);
		assertThat(grant.getType()).isEqualTo(GrantType.REFRESH_TOKEN);
		assertThat(grant.getRefreshToken()).isEqualTo(refreshToken);

		Map<String, List<String>> params = grant.toParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.REFRESH_TOKEN.getValue()));
		assertThat(params.get("refresh_token")).isEqualTo(Collections.singletonList(refreshToken.getValue()));
		assertThat(params).hasSize(2);
	}

	@Test
	public void testParse()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("refresh_token"));
		params.put("refresh_token", Collections.singletonList("abc123"));

		RefreshTokenGrant grant = RefreshTokenGrant.parse(params);
		assertThat(grant.getType()).isEqualTo(GrantType.REFRESH_TOKEN);
		assertThat(grant.getRefreshToken().getValue()).isEqualTo("abc123");
	}

	@Test
	public void testParse_missingGrantType()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("refresh_token", Collections.singletonList("abc123"));

		try {
			RefreshTokenGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"grant_type\" parameter");
		}
	}

	@Test
	public void testParse_unsupportedGrantType()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("unsupported"));
		params.put("refresh_token", Collections.singletonList("abc123"));

		try {
			RefreshTokenGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Unsupported grant type: The \"grant_type\" must be \"refresh_token\"");
		}
	}

	@Test
	public void testParse_missingRefreshToken()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("refresh_token"));

		try {
			RefreshTokenGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing or empty \"refresh_token\" parameter");
		}
	}

	@Test
	public void testEquality() {
		
		assertThat(new RefreshTokenGrant(new RefreshToken("xyz"))).isEqualTo(new RefreshTokenGrant(new RefreshToken("xyz")));
	}

	@Test
	public void testInequality() {

		assertThat(new RefreshTokenGrant(new RefreshToken("abc")).equals(new RefreshTokenGrant(new RefreshToken("xyz")))).isFalse();
	}
}
