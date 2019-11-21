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


import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.device.DeviceCodeGrant;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the abstract authorisation grant class.
 */
public class AuthorizationGrantTest{

	@Test
	public void testParseCode()
		throws Exception {
		
		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("authorization_code"));
		params.put("code", Collections.singletonList("abc"));
		params.put("redirect_uri", Collections.singletonList("https://client.com/in"));
		
		AuthorizationCodeGrant grant = (AuthorizationCodeGrant)AuthorizationGrant.parse(params);
		
		assertThat(grant.getType()).isEqualTo(GrantType.AUTHORIZATION_CODE);
		assertThat(grant.getAuthorizationCode().getValue()).isEqualTo("abc");
		assertThat(grant.getRedirectionURI().toString()).isEqualTo("https://client.com/in");
	}

	@Test
	public void testParseRefreshToken()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("refresh_token"));
		params.put("refresh_token", Collections.singletonList("abc123"));

		RefreshTokenGrant grant = (RefreshTokenGrant)AuthorizationGrant.parse(params);

		assertThat(grant.getType()).isEqualTo(GrantType.REFRESH_TOKEN);
		assertThat(grant.getRefreshToken().getValue()).isEqualTo("abc123");
	}

	@Test
	public void testParsePassword()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("password"));
		params.put("username", Collections.singletonList("alice"));
		params.put("password", Collections.singletonList("secret"));

		ResourceOwnerPasswordCredentialsGrant grant = (ResourceOwnerPasswordCredentialsGrant)AuthorizationGrant.parse(params);

		assertThat(grant.getType()).isEqualTo(GrantType.PASSWORD);
		assertThat(grant.getUsername()).isEqualTo("alice");
		assertThat(grant.getPassword().getValue()).isEqualTo("secret");
	}

	@Test
	public void testParseClientCredentials()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("client_credentials"));

		ClientCredentialsGrant grant = (ClientCredentialsGrant)AuthorizationGrant.parse(params);

		assertThat(grant.getType()).isEqualTo(GrantType.CLIENT_CREDENTIALS);
	}

	@Test
	public void testParseJWTBearer()
		throws Exception {

		// Claims set not verified
		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		SignedJWT assertion = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		assertion.sign(new MACSigner(new Secret().getValueBytes()));

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.JWT_BEARER.getValue()));
		params.put("assertion", Collections.singletonList(assertion.serialize()));

		JWTBearerGrant grant = (JWTBearerGrant)AuthorizationGrant.parse(params);

		assertThat(grant.getType()).isEqualTo(GrantType.JWT_BEARER);
		assertThat(grant.getAssertion()).isEqualTo(assertion.serialize());
		assertThat(grant.getJWTAssertion().getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
	}

	@Test
	public void testParseSAML2Bearer()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.SAML2_BEARER.getValue()));
		params.put("assertion", Collections.singletonList("abc"));

		SAML2BearerGrant grant = (SAML2BearerGrant)AuthorizationGrant.parse(params);

		assertThat(grant.getType()).isEqualTo(GrantType.SAML2_BEARER);
		assertThat(grant.getAssertion()).isEqualTo("abc");
		assertThat(grant.getSAML2Assertion().toString()).isEqualTo("abc");
	}

	@Test
	public void testParseDeviceCode()
		throws Exception {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.DEVICE_CODE.getValue()));
		params.put("device_code", Collections.singletonList("abc"));

		DeviceCodeGrant grant = (DeviceCodeGrant)AuthorizationGrant.parse(params);

		assertThat(grant.getType()).isEqualTo(GrantType.DEVICE_CODE);
		assertThat(grant.getDeviceCode().getValue()).isEqualTo("abc");
	}
}
