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

package be.atbash.ee.oauth2.sdk.auth;



import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests client secret basic authentication.
 */
public class ClientSecretPostTest {

	@Test
	public void testSerializeAndParse()
		throws OAuth2JSONParseException {

		// Test vectors from OAuth 2.0 RFC

		final String id = "s6BhdRkqt3";
		final String pw = "7Fjfp0ZBr1KtDRbnfVdmIw";

		ClientID clientID = new ClientID(id);
		Secret secret = new Secret(pw);

		ClientSecretPost csp = new ClientSecretPost(clientID, secret);

		assertThat(csp).isInstanceOf(PlainClientSecret.class);

		assertThat(csp.getMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_POST);

		assertThat(csp.getClientID().getValue()).isEqualTo(id);
		assertThat(csp.getClientSecret().getValue()).isEqualTo(pw);

		Map<String, List<String>> params = csp.toParameters();

		assertThat(params.get("client_id")).isEqualTo(Collections.singletonList(id));
		assertThat(params.get("client_secret")).isEqualTo(Collections.singletonList(pw));
		assertThat(params).hasSize(2);

		csp = ClientSecretPost.parse(params);

		assertThat(csp.getClientID().toString()).isEqualTo(id);
		assertThat(csp.getClientSecret().getValue()).isEqualTo(pw);
	}

	@Test
	public void testParse_missingClientID() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("client_secret", Collections.singletonList("secret"));
		try {
			ClientSecretPost.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Malformed client secret post authentication: Missing \"client_id\" parameter");
		}
	}

	@Test
	public void testParse_missingClientSecret() {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("client_id", Collections.singletonList("alice"));
		try {
			ClientSecretPost.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Malformed client secret post authentication: Missing \"client_secret\" parameter");
		}
	}
}
