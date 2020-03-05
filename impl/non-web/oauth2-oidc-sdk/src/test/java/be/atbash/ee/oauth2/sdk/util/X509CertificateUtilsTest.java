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
package be.atbash.ee.oauth2.sdk.util;



import be.atbash.ee.oauth2.sdk.http.X509CertificateGenerator;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.assertj.core.api.Assertions.assertThat;


public class X509CertificateUtilsTest {
	
	
	public static final RSAPublicKey PUBLIC_KEY;
	
	
	public static final RSAPrivateKey PRIVATE_KEY;
	
	
	static {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			PUBLIC_KEY = (RSAPublicKey)keyPair.getPublic();
			PRIVATE_KEY = (RSAPrivateKey)keyPair.getPrivate();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	public void testHasMatchingIssuerAndSubject_true()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("123"),
			PUBLIC_KEY,
			PRIVATE_KEY);
		
		assertThat(X509CertificateUtils.hasMatchingIssuerAndSubject(cert)).isTrue();
	}

	@Test
	public void testHasMatchingIssuerAndSubject_false()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			PUBLIC_KEY,
			PRIVATE_KEY);
		
		assertThat(X509CertificateUtils.hasMatchingIssuerAndSubject(cert)).isFalse();
	}

	@Test
	public void testIsSelfIssued_positive()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer("123"),
			PUBLIC_KEY,
			PRIVATE_KEY
		);
		
		assertThat(X509CertificateUtils.isSelfIssued(cert)).isTrue();
		assertThat(X509CertificateUtils.isSelfSigned(cert)).isTrue();
	}

	@Test
	public void testIsSelfIssued_negative()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			PUBLIC_KEY,
			PRIVATE_KEY
		);
		
		assertThat(X509CertificateUtils.isSelfIssued(cert)).isFalse();
		assertThat(X509CertificateUtils.isSelfSigned(cert)).isTrue();
	}

	@Test
	public void testPublicKeyMatches()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			PUBLIC_KEY,
			PRIVATE_KEY
		);
		
		assertThat(X509CertificateUtils.publicKeyMatches(cert, PUBLIC_KEY)).isTrue();
	}

	@Test
	public void testPublicKeyMatches_false()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			PUBLIC_KEY,
			PRIVATE_KEY
		);
		
		KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
		gen.initialize(2048);
		KeyPair keyPair = gen.generateKeyPair();
		PublicKey otherPublicKey = keyPair.getPublic();
		
		assertThat(X509CertificateUtils.publicKeyMatches(cert, otherPublicKey)).isFalse();
	}

	@Test
	public void testPublicKeyMatches_viaJWK()
		throws Exception {
		
		X509Certificate cert = X509CertificateGenerator.generateCertificate(
			new Issuer("123"),
			new Subject("456"),
			PUBLIC_KEY,
			PRIVATE_KEY
		);
		
		RSAKey rsaJWK = RSAKey.parse(cert);
		
		assertThat(X509CertificateUtils.publicKeyMatches(cert, rsaJWK.toPublicKey())).isTrue();
	}
}
