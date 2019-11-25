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



import be.atbash.ee.oauth2.sdk.auth.Secret;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the password grant.
 */
public class ResourceOwnerPasswordCredentialsGrantTest  {

	@Test
	public void testConstructor() {

		String username = "alice";
		Secret password = new Secret("secret");
		ResourceOwnerPasswordCredentialsGrant grant = new ResourceOwnerPasswordCredentialsGrant(username, password);
		assertThat(grant.getType()).isEqualTo(GrantType.PASSWORD);
		assertThat(grant.getUsername()).isEqualTo(username);
		assertThat(grant.getPassword()).isEqualTo(password);

		Map<String, List<String>> params = grant.toParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList("password"));
		assertThat(params.get("username")).isEqualTo(Collections.singletonList("alice"));
		assertThat(params.get("password")).isEqualTo(Collections.singletonList("secret"));
		assertThat(params).hasSize(3);
	}

	@Test
	public void testParse()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("password"));
		params.put("username", Collections.singletonList("alice"));
		params.put("password", Collections.singletonList("secret"));

		ResourceOwnerPasswordCredentialsGrant grant = ResourceOwnerPasswordCredentialsGrant.parse(params);
		assertThat(grant.getType()).isEqualTo(GrantType.PASSWORD);
		assertThat(grant.getUsername()).isEqualTo("alice");
		assertThat(grant.getPassword().getValue()).isEqualTo("secret");
	}

	@Test
	public void testParseMissingGrantType() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("username", Collections.singletonList("alice"));
		params.put("password", Collections.singletonList("secret"));

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"grant_type\" parameter");
		}
	}

	@Test
	public void testParseUnsupportedGrantType() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("invalid_grant"));
		params.put("username", Collections.singletonList("alice"));
		params.put("password", Collections.singletonList("secret"));

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Unsupported grant type: The \"grant_type\" must be password");
		}
	}

	@Test
	public void testParseMissingUsername() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("password"));
		params.put("password", Collections.singletonList("secret"));

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing or empty \"username\" parameter");
		}
	}

	@Test
	public void testParseMissingPassword() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("password"));
		params.put("username", Collections.singletonList("alice"));

		try {
			ResourceOwnerPasswordCredentialsGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing or empty \"password\" parameter");
		}
	}

	@Test
	public void testEquality() {

		assertThat(new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"))
			.equals(new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret")))).isTrue();
	}

	@Test
	public void testInequality() {

		assertThat(new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"))
			.equals(new ResourceOwnerPasswordCredentialsGrant("bob", new Secret("secret")))).isFalse();

		assertThat(new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"))
			.equals(new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("no-secret")))).isFalse();
	}
}
