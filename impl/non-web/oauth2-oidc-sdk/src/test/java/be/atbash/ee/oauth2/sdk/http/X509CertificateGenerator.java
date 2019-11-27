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
package be.atbash.ee.oauth2.sdk.http;


import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.security.octopus.nimbus.util.X509CertUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;


public class X509CertificateGenerator {


	public static X509Certificate generateCertificate(Issuer issuer,
													  Subject subject,
													  RSAPublicKey rsaPublicKey,
													  RSAPrivateKey rsaPrivateKey)
		throws IOException, OperatorCreationException {
		
		X500Name certIssuer = new X500Name("cn=" + issuer);
		BigInteger serialNumber = new BigInteger(64, new SecureRandom());
		Date now = new Date();
		Date nbf = new Date(now.getTime() - 1000L);
		Date exp = new Date(now.getTime() + 365*24*60*60*1000L); // in 1 year
		X500Name certSubject = new X500Name("cn=" + subject);
		JcaX509v3CertificateBuilder x509certBuilder = new JcaX509v3CertificateBuilder(
			certIssuer,
			serialNumber,
			nbf,
			exp,
			certSubject,
			rsaPublicKey
		);
		
		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
		X509CertificateHolder certHolder = x509certBuilder.build(signerBuilder.build(rsaPrivateKey));
		return X509CertUtils.parse(certHolder.getEncoded());
	}
	

	/**
	 * Technically this is not allowed (a self signed certificate should always be
	 * self issued), but for tests this is good enough to simulate a PKI certificate.
	 */
	public static X509Certificate generateSelfSignedNotSelfIssuedCertificate(String issuer,
																			 String subject)
		throws Exception {

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();

		return generateCertificate(new Issuer(issuer), new Subject(subject), rsaPublicKey, rsaPrivateKey);
	}

	public static X509Certificate generateSelfSignedCertificate(Issuer issuer,
																RSAPublicKey rsaPublicKey,
																RSAPrivateKey rsaPrivateKey)
		throws IOException, OperatorCreationException {
		
		return generateCertificate(issuer, new Subject(issuer.getValue()), rsaPublicKey, rsaPrivateKey);
	}
	
	
	public static X509Certificate generateSampleClientCertificate()
		throws Exception {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
		
		return X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer("123"),
			rsaPublicKey,
			rsaPrivateKey);
	}
}
