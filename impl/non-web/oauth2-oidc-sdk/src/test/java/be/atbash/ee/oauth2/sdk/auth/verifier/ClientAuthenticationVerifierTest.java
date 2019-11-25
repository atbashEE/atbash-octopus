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
package be.atbash.ee.oauth2.sdk.auth.verifier;


import be.atbash.ee.oauth2.sdk.auth.*;
import be.atbash.ee.oauth2.sdk.client.ClientMetadata;
import be.atbash.ee.oauth2.sdk.http.X509CertificateGenerator;
import be.atbash.ee.oauth2.sdk.id.*;
import be.atbash.ee.oauth2.sdk.util.X509CertificateUtils;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.Test;

import javax.net.ssl.SSLSocketFactory;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the client authentication verifier.
 */
public class ClientAuthenticationVerifierTest {


	private static final ClientID VALID_CLIENT_ID = new ClientID("123");


	private static final Secret VALID_CLIENT_SECRET = new Secret();


	private static final Set<Audience> EXPECTED_JWT_AUDIENCE = new LinkedHashSet<>(Arrays.asList(
		new Audience("https://c2id.com/token"),
		new Audience("https://c2id.com")));
	
	
	private static final String VALID_SUBJECT_DN = "cn=client-123";

	
	private static final RSAKey VALID_RSA_KEY_PAIR_1;


	private static final RSAKey VALID_RSA_KEY_PAIR_2;


	private static final RSAKey INVALID_RSA_KEY_PAIR;


	static {
		try {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");

			KeyPair keyPair = gen.generateKeyPair();
			VALID_RSA_KEY_PAIR_1 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("1")
				.build();

			keyPair = gen.generateKeyPair();
			VALID_RSA_KEY_PAIR_2 = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.keyID("2")
				.build();

			keyPair = gen.generateKeyPair();
			INVALID_RSA_KEY_PAIR = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey)keyPair.getPrivate())
				.build();

		} catch (Exception e) {
			throw new RuntimeException(e.getMessage(), e);
		}
	}


	private static final ClientCredentialsSelector<ClientMetadata> CLIENT_CREDENTIALS_SELECTOR = new ClientCredentialsSelector<ClientMetadata>() {


		@Override
		public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context<ClientMetadata> context)
			throws InvalidClientException {

			assert authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC) ||
				authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_POST) ||
				authMethod.equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT);

			if (! claimedClientID.equals(VALID_CLIENT_ID)) {
				throw InvalidClientException.BAD_ID;
			}

			return Collections.singletonList(VALID_CLIENT_SECRET);
		}


		@Override
		public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID,
                                                          ClientAuthenticationMethod authMethod,
                                                          JWSHeader jwsHeader,
                                                          boolean forceRefresh,
                                                          Context<ClientMetadata> context)
			throws InvalidClientException {

			final Set<ClientAuthenticationMethod> permittedClientAuthMethods =
				new HashSet<>(Arrays.asList(
					ClientAuthenticationMethod.PRIVATE_KEY_JWT,
					ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH));
			
			assert permittedClientAuthMethods.contains(authMethod);

			if (! claimedClientID.equals(VALID_CLIENT_ID)) {
				throw InvalidClientException.BAD_ID;
			}

			try {
				if (!forceRefresh) {
					return Collections.singletonList(VALID_RSA_KEY_PAIR_1.toRSAPublicKey());
				} else {
					// Simulate reload
					return Arrays.asList(VALID_RSA_KEY_PAIR_1.toRSAPublicKey(), VALID_RSA_KEY_PAIR_2.toRSAPublicKey());
				}

			} catch (JOSEException e) {
				fail(e.getMessage());
				throw InvalidClientException.NO_MATCHING_JWK;
			}
		}
	};
	
	
	private static final PKIClientX509CertificateBindingVerifier<ClientMetadata> CERT_BINDING_VERIFIER = new PKIClientX509CertificateBindingVerifier<ClientMetadata>() {
		
		@Override
		public void verifyCertificateBinding(ClientID clientID,
						     X509Certificate certificate,
						     Context<ClientMetadata> ctx)
			throws InvalidClientException {
			
			if (! VALID_CLIENT_ID.equals(clientID)) {
				throw InvalidClientException.BAD_ID;
			}
			
			if (! VALID_SUBJECT_DN.equalsIgnoreCase(certificate.getSubjectDN().getName())) {
				throw new InvalidClientException("Bad subject DN");
			}
		}
	};

	@Test
	public void testGetters() {

		ClientCredentialsSelector selector = new ClientCredentialsSelector() {
			@Override
			public List<Secret> selectClientSecrets(ClientID claimedClientID, ClientAuthenticationMethod authMethod, Context context) throws InvalidClientException {
				return null;
			}


			@Override
			public List<? extends PublicKey> selectPublicKeys(ClientID claimedClientID, ClientAuthenticationMethod authMethod, JWSHeader jwsHeader, boolean forceRefresh, Context context) throws InvalidClientException {
				return null;
			}
		};

		Set<Audience> audienceSet = new HashSet<>();
		audienceSet.add(new Audience("https://c2id.com/token"));

		ClientAuthenticationVerifier verifier = new ClientAuthenticationVerifier(selector, null, audienceSet);

		assertThat(verifier.getClientCredentialsSelector()).isEqualTo(selector);
		assertThat(verifier.getExpectedAudience()).isEqualTo(audienceSet);
	}


	private static ClientAuthenticationVerifier<ClientMetadata> createBasicVerifier() {

		return new ClientAuthenticationVerifier<>(CLIENT_CREDENTIALS_SELECTOR, null, EXPECTED_JWT_AUDIENCE);
	}
	
	
	private static ClientAuthenticationVerifier<ClientMetadata> createVerifierWithPKIBoundCertSupport() {
		
		return new ClientAuthenticationVerifier<>(CLIENT_CREDENTIALS_SELECTOR, CERT_BINDING_VERIFIER, EXPECTED_JWT_AUDIENCE);
	}

	@Test
	public void testHappyClientSecretBasic()
		throws Exception {

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, VALID_CLIENT_SECRET);

		createBasicVerifier().verify(clientAuthentication, null, null);
	}

	@Test
	public void testHappyClientSecretPost()
		throws Exception {

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, VALID_CLIENT_SECRET);

		createBasicVerifier().verify(clientAuthentication, null, null);
	}

	@Test
	public void testHappyClientSecretJWT()
		throws Exception {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			VALID_CLIENT_SECRET);

		createBasicVerifier().verify(clientAuthentication, null, null);
	}

	@Test
	public void testHappyPrivateKeyJWT()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_1.toRSAPrivateKey(),
			null,
			null);

		createBasicVerifier().verify(clientAuthentication, null, null);
	}

	@Test
	public void testInvalidClientSecretPost_badID()
		throws JOSEException{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(new ClientID("invalid-id"), VALID_CLIENT_SECRET);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertThat(e).isEqualTo(InvalidClientException.BAD_ID);
		}
	}

	@Test
	public void testInvalidClientSecretPost_badSecret()
		throws JOSEException{

		ClientAuthentication clientAuthentication = new ClientSecretBasic(VALID_CLIENT_ID, new Secret("invalid-secret"));

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertThat(e).isEqualTo(InvalidClientException.BAD_SECRET);
		}
	}

	@Test
	public void testInvalidClientSecretJWT_badHMAC()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://c2id.com/token"),
			JWSAlgorithm.HS256,
			new Secret());

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertThat(e).isEqualTo(InvalidClientException.BAD_JWT_HMAC);
		}
	}

	@Test
	public void testInvalidPrivateKeyJWT_badSignature()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey(),
			null,
			null);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertThat(e).isEqualTo(InvalidClientException.BAD_JWT_SIGNATURE);
		}
	}

	@Test
	public void testClientSecretJWTBadAudience()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new ClientSecretJWT(
			VALID_CLIENT_ID,
			URI.create("https://other.com/token"),
			JWSAlgorithm.HS256,
			new Secret());

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertThat(e.getMessage()).isEqualTo("Bad / expired JWT claims: Invalid JWT audience claim, expected [https://c2id.com/token, https://c2id.com]");
		}
	}

	@Test
	public void testPrivateKeyJWTBadAudience()
		throws JOSEException {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://other.com/token"),
			JWSAlgorithm.RS256,
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey(),
			null,
			null);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertThat(e.getMessage()).isEqualTo("Bad / expired JWT claims: Invalid JWT audience claim, expected [https://c2id.com/token, https://c2id.com]");
		}
	}

	@Test
	public void testExpiredClientSecretJWT()
		throws JOSEException {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000L);

		JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(
			VALID_CLIENT_ID,
			EXPECTED_JWT_AUDIENCE.iterator().next().toSingleAudienceList(),
			before5min,
			null,
			now,
			new JWTID());

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());
		jwt.sign(new MACSigner(VALID_CLIENT_SECRET.getValueBytes()));

		ClientAuthentication clientAuthentication = new ClientSecretJWT(jwt);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertThat(e.getMessage()).isEqualTo("Bad / expired JWT claims: Expired JWT");
		}
	}

	@Test
	public void testExpiredPrivateKeyJWT()
		throws JOSEException {

		Date now = new Date();
		Date before5min = new Date(now.getTime() - 5*60*1000L);

		JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(
			VALID_CLIENT_ID,
			EXPECTED_JWT_AUDIENCE.iterator().next().toSingleAudienceList(),
			before5min,
			null,
			now,
			new JWTID());

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet.toJWTClaimsSet());
		jwt.sign(new RSASSASigner(VALID_RSA_KEY_PAIR_1));

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(jwt);

		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
		} catch (InvalidClientException e) {
			assertThat(e.getMessage()).isEqualTo("Bad / expired JWT claims: Expired JWT");
		}
	}

	@Test
	public void testReloadRemoteJWKSet()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			VALID_RSA_KEY_PAIR_2.toRSAPrivateKey(),
			null,
			null);

		createBasicVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
	}

	@Test
	public void testReloadRemoteJWKSet_badSignature()
		throws Exception {

		ClientAuthentication clientAuthentication = new PrivateKeyJWT(
			VALID_CLIENT_ID, URI.create("https://c2id.com/token"),
			JWSAlgorithm.RS256,
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey(),
			null,
			null);

		try {
			createBasicVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
		} catch (InvalidClientException e) {
			assertThat(e).isEqualTo(InvalidClientException.BAD_JWT_SIGNATURE);
		}
	}

	@Test
	public void testPubKeyTLSClientAuth_ok()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer(VALID_CLIENT_ID),
			VALID_RSA_KEY_PAIR_1.toRSAPublicKey(),
			VALID_RSA_KEY_PAIR_1.toRSAPrivateKey()
		);
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		createBasicVerifier().verify(clientAuthentication, null, null);
	}

	@Test
	public void testPubKeyTLSClientAuth_signedByCA_ok()
		throws Exception {
		
		// Generate CA key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey caRSAPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey caRSAPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
		
		X509Certificate clientCert = X509CertificateGenerator.generateCertificate(
			new Issuer("o=c2id"),
			new Subject(VALID_CLIENT_ID.getValue()),
			VALID_RSA_KEY_PAIR_1.toRSAPublicKey(), // client public key
			caRSAPrivateKey // CA private key
		);
		
		assertThat(X509CertificateUtils.hasValidSignature(clientCert, caRSAPublicKey)).isTrue();
		assertThat(X509CertificateUtils.publicKeyMatches(clientCert, VALID_RSA_KEY_PAIR_1.toRSAPublicKey())).isTrue();
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		createBasicVerifier().verify(clientAuthentication, null, null);
	}

	@Test
	public void testPubKeyTLSClientAuth_okWithReload()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer(VALID_CLIENT_ID),
			VALID_RSA_KEY_PAIR_2.toRSAPublicKey(),
			VALID_RSA_KEY_PAIR_2.toRSAPrivateKey()
		);
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		createBasicVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
	}

	@Test
	public void testPubKeyTLSClientAuth_signedByCA_okWithReload()
		throws Exception {
		
		// Generate CA key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey caRSAPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey caRSAPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
		
		X509Certificate clientCert = X509CertificateGenerator.generateCertificate(
			new Issuer("o=c2id"),
			new Subject(VALID_CLIENT_ID.getValue()),
			VALID_RSA_KEY_PAIR_1.toRSAPublicKey(), // client public key
			caRSAPrivateKey // CA private key
		);
		
		assertThat(X509CertificateUtils.hasValidSignature(clientCert, caRSAPublicKey)).isTrue();
		assertThat(X509CertificateUtils.publicKeyMatches(clientCert, VALID_RSA_KEY_PAIR_1.toRSAPublicKey())).isTrue();
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		createBasicVerifier().verify(clientAuthentication, Collections.singleton(Hint.CLIENT_HAS_REMOTE_JWK_SET), null);
	}

	@Test
	public void testPubKeyTLSClientAuth_badSignature()
		throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer(VALID_CLIENT_ID),
			INVALID_RSA_KEY_PAIR.toRSAPublicKey(),
			INVALID_RSA_KEY_PAIR.toRSAPrivateKey()
		);
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertThat(e.getMessage()).isEqualTo("Couldn't validate client X.509 certificate signature: No matching registered client JWK found");
		}
	}

	@Test
	public void testPubKeyTLSClientAuth_signedByCA_badSignature()
		throws Exception {
		
		// Generate CA key pair
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey caRSAPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey caRSAPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
		
		X509Certificate clientCert = X509CertificateGenerator.generateCertificate(
			new Issuer("o=c2id"),
			new Subject(VALID_CLIENT_ID.getValue()),
			INVALID_RSA_KEY_PAIR.toRSAPublicKey(), // client public key that isn't registered
			caRSAPrivateKey // CA private key
		);
		
		assertThat(X509CertificateUtils.hasValidSignature(clientCert, caRSAPublicKey)).isTrue();
		assertThat(X509CertificateUtils.publicKeyMatches(clientCert, INVALID_RSA_KEY_PAIR.toRSAPublicKey())).isTrue();
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			clientCert
		);
		
		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertThat(e.getMessage()).isEqualTo("Couldn't validate client X.509 certificate signature: No matching registered client JWK found");
		}
	}

	@Test
	public void testPubKeyTLSClientAuth_missingCertificate()
		throws Exception {
		
		ClientAuthentication clientAuthentication = new SelfSignedTLSClientAuthentication(
			VALID_CLIENT_ID,
			(SSLSocketFactory) null);
		
		try {
			createBasicVerifier().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertThat(e.getMessage()).isEqualTo("Missing client X.509 certificate");
		}
	}

	@Test
	public void testTLSClientAuth_ok()
		throws Exception {
		
		ClientAuthentication clientAuthentication = new PKITLSClientAuthentication(
			VALID_CLIENT_ID,
			X509CertificateGenerator.generateSelfSignedNotSelfIssuedCertificate("issuer", "client-123")
		);
		
		createVerifierWithPKIBoundCertSupport().verify(clientAuthentication, null, null);
	}

	@Test
	public void testTLSClientAuth_badSubjectDN()
		throws Exception {
		
		ClientAuthentication clientAuthentication = new PKITLSClientAuthentication(
			VALID_CLIENT_ID,
			X509CertificateGenerator.generateSelfSignedNotSelfIssuedCertificate("issuer", "invalid-subject")
		);
		
		try {
			createVerifierWithPKIBoundCertSupport().verify(clientAuthentication, null, null);
			fail();
		} catch (InvalidClientException e) {
			assertThat(e.getMessage()).isEqualTo("Bad subject DN");
		}
	}
}
