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



import be.atbash.ee.oauth2.sdk.auth.PKITLSClientAuthentication;
import be.atbash.ee.oauth2.sdk.auth.SelfSignedTLSClientAuthentication;
import be.atbash.ee.oauth2.sdk.auth.TLSClientAuthentication;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.http.X509CertificateGenerator;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.PlainJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.net.ssl.SSLSocketFactory;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class RequestObjectPOSTRequestTest  {
	
	
	private static JWT createRequestJWT() throws JOSEException {
		
		RSAKey rsaJWK = generateKey();
		
		AuthorizationRequest ar = new AuthorizationRequest.Builder(
			new ResponseType(ResponseType.Value.CODE),
			new ClientID("123"))
			.redirectionURI(URI.create("https://example.com/cb"))
			.state(new State())
			.build();
		
		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), ar.toJWTClaimsSet());
		jwt.sign(new RSASSASigner(rsaJWK));
		return jwt;
	}

	private static RSAKey generateKey() {
		KeyGenerator keyGenerator = new KeyGenerator();
		keyGenerator.init();
		RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
				.withKeySize(2048)
				.withKeyId("s1")
				.build();
		List<AtbashKey> atbashKeys = keyGenerator.generateKeys(generationParameters);

		ListKeyManager keyManager = new ListKeyManager(atbashKeys);

		SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
		List<AtbashKey> privateList = keyManager.retrieveKeys(criteria);

		AtbashKey privateKey = privateList.get(0);
		criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PUBLIC).build();

		List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);
		AtbashKey publicKey = publicList.get(0);


		return new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid")
				.privateKey((RSAPrivateKey) privateKey.getKey())
				.build();


	}
	@Test
	public void testJWTLifeCycle() throws Exception {
		
		JWT jwt = createRequestJWT();
		
		URI endpoint = URI.create("https://c2id.com/requests");
		RequestObjectPOSTRequest postRequest = new RequestObjectPOSTRequest(endpoint, jwt);
		assertThat(postRequest.getEndpointURI()).isEqualTo(endpoint);
		assertThat(postRequest.getClientAuthentication()).isNull();
		assertThat(postRequest.getTLSClientAuthentication()).isNull();
		assertThat(postRequest.getRequestObject()).isEqualTo(jwt);
		assertThat(postRequest.getRequestJSONObject()).isNull();
		
		HTTPRequest httpRequest = postRequest.toHTTPRequest();
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_JWT.toString());
		assertThat(httpRequest.getQuery()).isEqualTo(jwt.serialize());
		
		postRequest = RequestObjectPOSTRequest.parse(httpRequest);
		assertThat(postRequest.getEndpointURI()).isEqualTo(endpoint);
		assertThat(postRequest.getClientAuthentication()).isNull();
		assertThat(postRequest.getTLSClientAuthentication()).isNull();
		assertThat(postRequest.getRequestObject().serialize()).isEqualTo(jwt.serialize());
		assertThat(postRequest.getRequestJSONObject()).isNull();
	}
	
	
	// Plain JSON object with self-signed mTLS
	@Test
	public void testJSONObjectLifeCycle_selfSignedTLSClientAuth() throws Exception {
		
		X509Certificate clientCert = X509CertificateGenerator.generateSampleClientCertificate();
		
		JsonObject jsonObject = createRequestJWT().getJWTClaimsSet().toJSONObject();
		
		URI endpoint = URI.create("https://c2id.com/requests");
		TLSClientAuthentication clientAuth = new SelfSignedTLSClientAuthentication(new ClientID("123"), (SSLSocketFactory) null);
		RequestObjectPOSTRequest postRequest = new RequestObjectPOSTRequest(endpoint, clientAuth, jsonObject);
		assertThat(postRequest.getEndpointURI()).isEqualTo(endpoint);
		assertThat(postRequest.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(postRequest.getTLSClientAuthentication()).isEqualTo(clientAuth);
		assertThat(postRequest.getRequestObject()).isNull();
		assertThat(postRequest.getRequestJSONObject()).isEqualTo(jsonObject);
		
		HTTPRequest httpRequest = postRequest.toHTTPRequest();
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_JSON.toString());
		assertThat(httpRequest.getClientX509Certificate()).isNull();
		assertThat(httpRequest.getClientX509CertificateSubjectDN()).isNull();
		assertThat(httpRequest.getQueryAsJSONObject()).isEqualTo(jsonObject);
		
		httpRequest.setClientX509Certificate(clientCert); // simulate reverse proxy
		httpRequest.setClientX509CertificateRootDN(clientCert.getIssuerDN().getName());
		httpRequest.setClientX509CertificateSubjectDN(clientCert.getSubjectDN().getName());
		postRequest = RequestObjectPOSTRequest.parse(httpRequest);
		
		assertThat(postRequest.getEndpointURI()).isEqualTo(endpoint);
		SelfSignedTLSClientAuthentication selfSignedTLSClientAuth = (SelfSignedTLSClientAuthentication) postRequest.getTLSClientAuthentication();
		assertThat(selfSignedTLSClientAuth.getClientID()).isEqualTo(clientAuth.getClientID());
		assertThat(selfSignedTLSClientAuth.getClientX509Certificate()).isEqualTo(clientCert);
		assertThat(postRequest.getRequestObject()).isNull();
		assertThat(postRequest.getRequestJSONObject()).isEqualTo(jsonObject);
	}
	
	
	// Plain JSON object with PKI-based mTLS
	@Test
	public void testJSONObjectLifeCycle_PKITLSClientAuth() throws Exception {
		
		JsonObject jsonObject = createRequestJWT().getJWTClaimsSet().toJSONObject();
		
		URI endpoint = URI.create("https://c2id.com/requests");
		TLSClientAuthentication clientAuth = new PKITLSClientAuthentication(new ClientID("123"), (SSLSocketFactory) null);
		RequestObjectPOSTRequest postRequest = new RequestObjectPOSTRequest(endpoint, clientAuth, jsonObject);
		assertThat(postRequest.getEndpointURI()).isEqualTo(endpoint);
		assertThat(postRequest.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(postRequest.getTLSClientAuthentication()).isEqualTo(clientAuth);
		assertThat(postRequest.getRequestObject()).isNull();
		assertThat(postRequest.getRequestJSONObject()).isEqualTo(jsonObject);
		
		HTTPRequest httpRequest = postRequest.toHTTPRequest();
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_JSON.toString());
		assertThat(httpRequest.getClientX509Certificate()).isNull();
		assertThat(httpRequest.getClientX509CertificateSubjectDN()).isNull();
		assertThat(httpRequest.getQueryAsJSONObject()).isEqualTo(jsonObject);
		
		httpRequest.setClientX509Certificate(X509CertificateGenerator.generateSelfSignedNotSelfIssuedCertificate(
				"issuer", "123")); // simulate reverse proxy
		postRequest = RequestObjectPOSTRequest.parse(httpRequest);
		
		assertThat(postRequest.getEndpointURI()).isEqualTo(endpoint);
		PKITLSClientAuthentication pkiTLSClientAuth = (PKITLSClientAuthentication) postRequest.getTLSClientAuthentication();
		assertThat(pkiTLSClientAuth.getClientID()).isEqualTo(clientAuth.getClientID());
		assertThat(postRequest.getRequestObject()).isNull();
		assertThat(postRequest.getRequestJSONObject()).isEqualTo(jsonObject);
	}

	@Test
	public void testRejectNullJWT() {
		
		try {
			new RequestObjectPOSTRequest(
				URI.create("https://c2id.com/requests"),
				null);
			
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The request object must not be null");
		}
	}

	@Test
	public void testRejectUnsecuredJWT() throws ParseException, JOSEException {
		
		JWT jwt = createRequestJWT();
		
		try {
			new RequestObjectPOSTRequest(
				URI.create("https://c2id.com/requests"),
				new PlainJWT(jwt.getJWTClaimsSet()));
			
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The request object must not be an unsecured JWT (alg=none)");
		}
	}

	@Test
	public void testRejectJSONObjectWithMissingTLSClientAuth() {
		
		try {
			new RequestObjectPOSTRequest(
				URI.create("https://c2id.com/requests"),
				null,
					Json.createObjectBuilder().build());
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The mutual TLS client authentication must not be null");
		}
	}

	@Test
	public void testRejectNullJSONObject() {
		
		try {
			new RequestObjectPOSTRequest(
				URI.create("https://c2id.com/requests"),
				new SelfSignedTLSClientAuthentication(new ClientID("123"), (SSLSocketFactory)null),
				null);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The request JSON object must not be null");
		}
	}
}
