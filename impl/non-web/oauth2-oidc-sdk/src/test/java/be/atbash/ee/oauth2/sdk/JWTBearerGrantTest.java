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
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.DirectDecrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.DirectEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.bc.BouncyCastleProviderSingleton;
import be.atbash.ee.security.octopus.nimbus.jwt.EncryptedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.PlainJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the JWT bearer grant.
 */
public class JWTBearerGrantTest  {

	@Test
	public void testRejectUnsignedAssertion() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		try {
			new JWTBearerGrant(new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet));
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The JWT assertion must not be in a unsigned state");
		}
	}

	@Test
	public void testRejectUnencryptedAssertion() {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		try {
			new JWTBearerGrant(new EncryptedJWT(new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128CBC_HS256), claimsSet));
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The JWT assertion must not be in a unencrypted state");
		}
	}

	@Test
	public void testSignedJWTConstructorAndParser()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		SignedJWT assertion = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

		assertion.sign(new MACSigner(new Secret().getValueBytes()));

		JWTBearerGrant grant = new JWTBearerGrant(assertion);

		assertThat(grant.getType()).isEqualTo(GrantType.JWT_BEARER);
		assertThat(grant.getJWTAssertion()).isEqualTo(assertion);
		assertThat(grant.getAssertion()).isEqualTo(assertion.serialize());

		Map<String, List<String>> params = grant.toParameters();
		assertThat(MultivaluedMapUtils.getFirstValue(params, "grant_type")).isEqualTo(GrantType.JWT_BEARER.getValue());
		assertThat(MultivaluedMapUtils.getFirstValue(params, "assertion")).isEqualTo(assertion.serialize());
		assertThat(params).hasSize(2);

		grant = JWTBearerGrant.parse(params);
		assertThat(grant.getType()).isEqualTo(GrantType.JWT_BEARER);
		assertThat(grant.getJWTAssertion()).isInstanceOf(SignedJWT.class);
		assertThat(grant.getAssertion()).isEqualTo(assertion.serialize());
	}

	@Test
	public void testEncryptedJWTConstructorAndParser()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		EncryptedJWT assertion = new EncryptedJWT(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256), claimsSet);

		byte[] secret = new byte[32];
		new SecureRandom().nextBytes(secret);

		assertion.encrypt(new DirectEncrypter(secret));

		JWTBearerGrant grant = new JWTBearerGrant(assertion);

		assertThat(grant.getType()).isEqualTo(GrantType.JWT_BEARER);
		assertThat(grant.getJWTAssertion()).isEqualTo(assertion);
		assertThat(grant.getAssertion()).isEqualTo(assertion.serialize());

		Map<String, List<String>> params = grant.toParameters();
		assertThat(MultivaluedMapUtils.getFirstValue(params, "grant_type")).isEqualTo(GrantType.JWT_BEARER.getValue());
		assertThat(MultivaluedMapUtils.getFirstValue(params, "assertion")).isEqualTo(assertion.serialize());
		assertThat(params).hasSize(2);

		grant = JWTBearerGrant.parse(params);
		assertThat(grant.getType()).isEqualTo(GrantType.JWT_BEARER);
		assertThat(grant.getJWTAssertion()).isInstanceOf(EncryptedJWT.class);
		assertThat(grant.getAssertion()).isEqualTo(assertion.serialize());
	}

	@Test
	public void testParseInvalidGrantType()
		throws JOSEException {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		SignedJWT assertion = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		assertion.sign(new MACSigner(new Secret().getValueBytes()));

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList("invalid-grant"));
		params.put("assertion", Collections.singletonList(assertion.serialize()));

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Unsupported grant type: The \"grant_type\" must be urn:ietf:params:oauth:grant-type:jwt-bearer");
		}
	}

	@Test
	public void testParseMissingAssertion() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.JWT_BEARER.getValue()));

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing or empty \"assertion\" parameter");
		}
	}

	@Test
	public void testParseInvalidJWTAssertion() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.JWT_BEARER.getValue()));
		params.put("assertion", Collections.singletonList("invalid-jwt"));

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: The \"assertion\" is not a JWT");
		}
	}

	@Test
	public void testParseRejectPlainJWT() {

		Map<String, List<String>> params = new HashMap<>();
		params.put("grant_type", Collections.singletonList(GrantType.JWT_BEARER.getValue()));
		params.put("assertion", Collections.singletonList(new PlainJWT(new JWTClaimsSet.Builder().subject("alice").build()).serialize()));

		try {
			JWTBearerGrant.parse(params);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: The JWT assertion must not be unsecured (plain)");
		}
	}

	@Test
	public void testEncryptedJWT()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

		EncryptedJWT jwt = new EncryptedJWT(header, claimsSet);

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();

		DirectEncrypter encrypter = new DirectEncrypter(key);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jwt.encrypt(encrypter);

		JWTBearerGrant jwtBearerGrant = new JWTBearerGrant(jwt);

		Map<String, List<String>> params = jwtBearerGrant.toParameters();

		jwtBearerGrant = JWTBearerGrant.parse(params);

		jwt = (EncryptedJWT)jwtBearerGrant.getJWTAssertion();
		assertThat(jwt).isNotNull();

		DirectDecrypter decrypter = new DirectDecrypter(key);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jwt.decrypt(decrypter);
		assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
	}

	@Test
	public void testEncryptedJWT_asJOSEObject()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.subject("alice")
			.build();

		JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

		EncryptedJWT jwt = new EncryptedJWT(header, claimsSet);

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();

		DirectEncrypter encrypter = new DirectEncrypter(key);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jwt.encrypt(encrypter);

		JWTBearerGrant jwtBearerGrant = new JWTBearerGrant(jwt);

		Map<String, List<String>> params = jwtBearerGrant.toParameters();

		jwtBearerGrant = JWTBearerGrant.parse(params);

		jwt = (EncryptedJWT)jwtBearerGrant.getJOSEAssertion();
		assertThat(jwt).isNotNull();

		DirectDecrypter decrypter = new DirectDecrypter(key);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jwt.decrypt(decrypter);
		assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
	}

	@Test
	public void testNestedJWT()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.subject("alice")
				.build();

		// Sign
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
		SignedJWT jwt = new SignedJWT(jwsHeader, claimsSet);
		Secret secret = new Secret();
		jwt.sign(new MACSigner(secret.getValueBytes()));


		// Encrypt
		JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM)
				.contentType("JWT")
				.build();

		JWEObject jweObject = new JWEObject(jweHeader, new Payload(jwt));

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();

		DirectEncrypter encrypter = new DirectEncrypter(key);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		JWTBearerGrant jwtBearerGrant = new JWTBearerGrant(jweObject);

		Map<String, List<String>> params = jwtBearerGrant.toParameters();

		jwtBearerGrant = JWTBearerGrant.parse(params);

		assertThat(jwtBearerGrant.getJWTAssertion()).isNull();

		jweObject = (JWEObject)jwtBearerGrant.getJOSEAssertion();

		DirectDecrypter decrypter = new DirectDecrypter(key);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		jwt = jweObject.getPayload().toSignedJWT();

		assertThat(jwt.verify(new MACVerifier(secret.getValueBytes()))).isTrue();

		assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
	}

	@Test
	public void testNestedJWT_ctyLowerCase()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.subject("alice")
				.build();

		// Sign
		JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);
		SignedJWT jwt = new SignedJWT(jwsHeader, claimsSet);
		Secret secret = new Secret();
		jwt.sign(new MACSigner(secret.getValueBytes()));


		// Encrypt
		JWEHeader jweHeader = new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128GCM)
				.contentType("jwt")
				.build();

		JWEObject jweObject = new JWEObject(jweHeader, new Payload(jwt));

		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey key = keyGen.generateKey();

		DirectEncrypter encrypter = new DirectEncrypter(key);
		encrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.encrypt(encrypter);

		JWTBearerGrant jwtBearerGrant = new JWTBearerGrant(jweObject);

		Map<String, List<String>> params = jwtBearerGrant.toParameters();

		jwtBearerGrant = JWTBearerGrant.parse(params);

		assertThat(jwtBearerGrant.getJWTAssertion()).isNull();

		jweObject = (JWEObject)jwtBearerGrant.getJOSEAssertion();

		DirectDecrypter decrypter = new DirectDecrypter(key);
		decrypter.getJCAContext().setContentEncryptionProvider(BouncyCastleProviderSingleton.getInstance());
		jweObject.decrypt(decrypter);

		jwt = jweObject.getPayload().toSignedJWT();

		assertThat(jwt.verify(new MACVerifier(secret.getValueBytes()))).isTrue();

		assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo("alice");
	}
}
