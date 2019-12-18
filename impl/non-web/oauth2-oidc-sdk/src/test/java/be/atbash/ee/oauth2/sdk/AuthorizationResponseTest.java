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


import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.jarm.JARMUtils;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the authorisation response class.
 */
public class AuthorizationResponseTest {

    private static final RSAPrivateKey RSA_PRIVATE_KEY;

    private static final RSAPublicKey RSA_PUBLIC_KEY;

    static {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair keyPair = gen.generateKeyPair();
            RSA_PRIVATE_KEY = (RSAPrivateKey) keyPair.getPrivate();
            RSA_PUBLIC_KEY = (RSAPublicKey) keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }



	@Test
	public void testJARM_successLifeCycle_query()
		throws Exception {
		
		AuthorizationSuccessResponse successResponse = new AuthorizationSuccessResponse(
			URI.create("https://example.com/cb"),
			new AuthorizationCode(),
			null,
			new State(),
			ResponseMode.QUERY_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			successResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		JWT jwt = signedJWT;
		
		AuthorizationSuccessResponse jwtSuccessResponse = new AuthorizationSuccessResponse(
			successResponse.getRedirectionURI(),
			jwt,
			successResponse.getResponseMode());
		
		assertThat(jwtSuccessResponse.getRedirectionURI()).isEqualTo(successResponse.getRedirectionURI());
		assertThat(jwtSuccessResponse.getJWTResponse()).isEqualTo(jwt);
		assertThat(jwtSuccessResponse.getResponseMode()).isEqualTo(successResponse.getResponseMode());
		
		Map<String, List<String>> params = jwtSuccessResponse.toParameters();
		assertThat(MultivaluedMapUtils.getFirstValue(params, "response")).isEqualTo(jwt.serialize());
		assertThat(params.size()).isEqualTo(1);
		
		URI uri = jwtSuccessResponse.toURI();
		
		assertThat(uri.toString().startsWith(successResponse.getRedirectionURI().toString())).isTrue();
		assertThat(uri.getQuery()).isEqualTo("response=" + jwt.serialize());
		assertThat(uri.getFragment()).isNull();
		
	}

	@Test
	public void testJARM_successLifeCycle_fragment()
		throws Exception {
		
		AuthorizationSuccessResponse successResponse = new AuthorizationSuccessResponse(
			URI.create("https://example.com/cb"),
			null,
			new BearerAccessToken(),
			new State(),
			ResponseMode.FRAGMENT_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			successResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		JWT jwt = signedJWT;
		
		AuthorizationSuccessResponse jwtSuccessResponse = new AuthorizationSuccessResponse(
			successResponse.getRedirectionURI(),
			jwt,
			successResponse.getResponseMode());
		
		assertThat(jwtSuccessResponse.getRedirectionURI()).isEqualTo(successResponse.getRedirectionURI());
		assertThat(jwtSuccessResponse.getJWTResponse()).isEqualTo(jwt);
		assertThat(jwtSuccessResponse.getResponseMode()).isEqualTo(successResponse.getResponseMode());
		
		Map<String, List<String>> params = jwtSuccessResponse.toParameters();
		assertThat(MultivaluedMapUtils.getFirstValue(params, "response")).isEqualTo(jwt.serialize());
		assertThat(params.size()).isEqualTo(1);
		
		URI uri = jwtSuccessResponse.toURI();
		
		assertThat(uri.toString().startsWith(successResponse.getRedirectionURI().toString())).isTrue();
		assertThat(uri.getQuery()).isNull();
		assertThat(uri.getFragment()).isEqualTo("response=" + jwt.serialize());
		
	}

	@Test
	public void testJARM_errorLifeCycle_query()
		throws Exception {
		
		AuthorizationErrorResponse errorResponse = new AuthorizationErrorResponse(
			URI.create("https://example.com/cb"),
			OAuth2Error.ACCESS_DENIED,
			new State(),
			ResponseMode.QUERY_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			errorResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		JWT jwt = signedJWT;
		
		AuthorizationErrorResponse jwtErrorResponse = new AuthorizationErrorResponse(
			errorResponse.getRedirectionURI(),
			jwt,
			errorResponse.getResponseMode());
		
		assertThat(jwtErrorResponse.getRedirectionURI()).isEqualTo(errorResponse.getRedirectionURI());
		assertThat(jwtErrorResponse.getJWTResponse()).isEqualTo(jwt);
		assertThat(jwtErrorResponse.getResponseMode()).isEqualTo(errorResponse.getResponseMode());
		
		Map<String, List<String>> params = jwtErrorResponse.toParameters();
		assertThat(MultivaluedMapUtils.getFirstValue(params, "response")).isEqualTo(jwt.serialize());
		assertThat(params.size()).isEqualTo(1);
		
		URI uri = jwtErrorResponse.toURI();
		
		assertThat(uri.toString().startsWith(errorResponse.getRedirectionURI().toString())).isTrue();
		assertThat(uri.getQuery()).isEqualTo("response=" + jwt.serialize());
		assertThat(uri.getFragment()).isNull();
		
	}


	@Test
	public void testJARM_errorLifeCycle_fragment()
		throws Exception {
		
		AuthorizationErrorResponse errorResponse = new AuthorizationErrorResponse(
			URI.create("https://example.com/cb"),
			OAuth2Error.ACCESS_DENIED,
			new State(),
			ResponseMode.FRAGMENT_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			errorResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		JWT jwt = signedJWT;
		
		AuthorizationErrorResponse jwtErrorResponse = new AuthorizationErrorResponse(
			errorResponse.getRedirectionURI(),
			jwt,
			errorResponse.getResponseMode());
		
		assertThat(jwtErrorResponse.getRedirectionURI()).isEqualTo(errorResponse.getRedirectionURI());
		assertThat(jwtErrorResponse.getJWTResponse()).isEqualTo(jwt);
		assertThat(jwtErrorResponse.getResponseMode()).isEqualTo(errorResponse.getResponseMode());
		
		Map<String, List<String>> params = jwtErrorResponse.toParameters();
		assertThat(MultivaluedMapUtils.getFirstValue(params, "response")).isEqualTo(jwt.serialize());
		assertThat(params.size()).isEqualTo(1);
		
		URI uri = jwtErrorResponse.toURI();
		
		assertThat(uri.toString().startsWith(errorResponse.getRedirectionURI().toString())).isTrue();
		assertThat(uri.getQuery()).isNull();
		assertThat(uri.getFragment()).isEqualTo("response=" + jwt.serialize());
		
	}

}
