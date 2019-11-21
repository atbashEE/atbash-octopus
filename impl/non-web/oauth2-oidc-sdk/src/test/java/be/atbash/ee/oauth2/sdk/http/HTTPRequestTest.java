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

package be.atbash.ee.oauth2.sdk.http;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.mail.internet.ContentType;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static net.jadler.Jadler.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the HTTP request class.
 */
public class HTTPRequestTest {


	@Test
	public void testDefaultHostnameVerifier() {

		assertThat(HTTPRequest.getDefaultHostnameVerifier()).isEqualTo(HttpsURLConnection.getDefaultHostnameVerifier());
	}


	@Test
	public void testDefaultSSLSocketFactory() {

		assertThat(HTTPRequest.getDefaultSSLSocketFactory()).isNotNull();
	}

	
	@Test
	public void testConstructorAndAccessors()
		throws Exception {

		URL url = new URL("https://c2id.com/login");

		HTTPRequest request = new HTTPRequest(HTTPRequest.Method.POST, url);

		assertThat(request.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(request.getURL()).isEqualTo(url);

		request.ensureMethod(HTTPRequest.Method.POST);

		try {
			request.ensureMethod(HTTPRequest.Method.GET);
			fail();
		} catch (OAuth2JSONParseException e) {
			// ok
		}

		assertThat(request.getContentType()).isNull();
		request.setContentType(CommonContentTypes.APPLICATION_JSON);
		assertThat(request.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_JSON.toString());

		assertThat(request.getAuthorization()).isNull();
		request.setAuthorization("Bearer 123");
		assertThat(request.getAuthorization()).isEqualTo("Bearer 123");

		assertThat(request.getAccept()).isNull();
		request.setAccept("text/plain");
		assertThat(request.getAccept()).isEqualTo("text/plain");

		assertThat(request.getQuery()).isNull();
		request.setQuery("x=123&y=456");
		assertThat(request.getQuery()).isEqualTo("x=123&y=456");

		Map<String, List<String>> params = request.getQueryParameters();
		assertThat(params.get("x")).isEqualTo(Collections.singletonList("123"));
		assertThat(params.get("y")).isEqualTo(Collections.singletonList("456"));

		request.setQuery("{\"apples\":\"123\"}");
		JsonObject jsonObject = request.getQueryAsJSONObject();
		assertThat(jsonObject.getString("apples")).isEqualTo("123");

		request.setFragment("fragment");
		assertThat(request.getFragment()).isEqualTo("fragment");

		assertThat(request.getConnectTimeout()).isEqualTo(0);
		request.setConnectTimeout(250);
		assertThat(request.getConnectTimeout()).isEqualTo(250);

		assertThat(request.getReadTimeout()).isEqualTo(0);
		request.setReadTimeout(750);
		assertThat(request.getReadTimeout()).isEqualTo(750);

		assertThat(request.getFollowRedirects()).isTrue();
		request.setFollowRedirects(false);
		assertThat(request.getFollowRedirects()).isFalse();
	}


	@Test
	public void testParseJSONObject()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost"));

		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

		httpRequest.setQuery("{\"apples\":30, \"pears\":\"green\"}");

		JsonObject jsonObject = httpRequest.getQueryAsJSONObject();

		assertThat(jsonObject.getInt("apples")).isEqualTo(30);
		assertThat(jsonObject.getString( "pears")).isEqualTo("green");
		assertThat(jsonObject).hasSize(2);
	}


	@Test
	public void testParseJSONObjectException()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost"));

		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

		httpRequest.setQuery(" ");

		try {
			httpRequest.getQueryAsJSONObject();
			fail();
		} catch (OAuth2JSONParseException e) {
			// ok
			assertThat(e.getMessage()).isEqualTo("Missing or empty HTTP query string / entity body");
		}
	}


	@Before
	public void setUp() {
		initJadler();
	}


	@After
	public void tearDown() {
		closeJadler();
	}


	@Test
	public void test401Response()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("POST")
			.havingHeaderEqualTo("Authorization", "Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW")
			.havingHeaderEqualTo("Content-Type", CommonContentTypes.APPLICATION_URLENCODED.toString())
			.havingPathEqualTo("/c2id/token")
			.havingBodyEqualTo("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
				"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb")
			.respond()
			.withStatus(401)
			.withHeader("WWW-Authenticate", "Bearer");

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/c2id/token"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		HTTPResponse httpResponse = httpRequest.send();
		assertThat(httpResponse.getStatusCode()).isEqualTo(401);
		assertThat(httpResponse.getStatusMessage()).isEqualTo("Unauthorized");
		assertThat(httpResponse.getWWWAuthenticate()).isEqualTo("Bearer");
	}


	@Test
	public void test404Response()
		throws Exception {

		onRequest()
			.respond()
			.withStatus(404);

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/c2id/.well-known/openid"));

		HTTPResponse httpResponse = httpRequest.send();
		assertThat(httpResponse.getStatusCode()).isEqualTo(404);
		assertThat(httpResponse.getStatusMessage()).isEqualTo("Not Found");
	}


	@Test
	public void test405Response()
		throws Exception {

		onRequest()
			.respond()
			.withStatus(405);

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/c2id/.well-known/openid"));

		HTTPResponse httpResponse = httpRequest.send();
		assertThat(httpResponse.getStatusCode()).isEqualTo(405);
		assertThat(httpResponse.getStatusMessage()).isEqualTo("Method Not Allowed");
	}


	@Test
	public void testToHttpURLConnection()
		throws Exception {

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/c2id/token"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setConnectTimeout(250);
		httpRequest.setReadTimeout(750);
		httpRequest.setQuery("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		HttpURLConnection con = httpRequest.toHttpURLConnection();
		assertThat(con.getRequestMethod()).isEqualTo("POST");
		assertThat(con.getConnectTimeout()).isEqualTo(250);
		assertThat(con.getReadTimeout()).isEqualTo(750);
		assertThat(con.getInstanceFollowRedirects()).isTrue();
	}


	@Test
	public void testToHttpURLConnectionAlt()
		throws Exception {

		// Simulate token request with invalid token
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("http://localhost:" + port() + "/c2id/token"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW");
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setConnectTimeout(250);
		httpRequest.setReadTimeout(750);
		httpRequest.setFollowRedirects(false);
		httpRequest.setQuery("grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

		HttpURLConnection con = httpRequest.toHttpURLConnection();
		assertThat(con.getRequestMethod()).isEqualTo("POST");
		assertThat(con.getConnectTimeout()).isEqualTo(250);
		assertThat(con.getReadTimeout()).isEqualTo(750);
		assertThat(con.getInstanceFollowRedirects()).isFalse();
	}


	@Test
	public void testSend()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("GET")
			.havingHeaderEqualTo("Authorization", "Bearer xyz")
			.havingHeaderEqualTo("Accept", CommonContentTypes.APPLICATION_JSON.toString())
			.havingPathEqualTo("/path")
			.havingQueryStringEqualTo("apples=10&pears=20")
			.respond()
			.withStatus(200)
			.withBody("[10, 20]")
			.withEncoding(Charset.forName("UTF-8"))
			.withContentType(CommonContentTypes.APPLICATION_JSON.toString());

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/path"));
		httpRequest.setQuery("apples=10&pears=20");
		httpRequest.setFragment("fragment");
		httpRequest.setAuthorization("Bearer xyz");
		httpRequest.setAccept(CommonContentTypes.APPLICATION_JSON.toString());

		HTTPResponse httpResponse = httpRequest.send();

		assertThat(httpResponse.getStatusCode()).isEqualTo(200);
		assertThat(httpResponse.getStatusMessage()).isEqualTo("OK");
		httpResponse.ensureContentType(CommonContentTypes.APPLICATION_JSON);

		JsonArray jsonArray = httpResponse.getContentAsJSONArray();
		assertThat(jsonArray.getJsonNumber(0).longValue()).isEqualTo(10L);
		assertThat(jsonArray.getJsonNumber(1).longValue()).isEqualTo(20L);
		assertThat(jsonArray).hasSize(2);
	}


	@Test
	public void testWithOtherResponseHeaders()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("GET")
			.havingHeaderEqualTo("Authorization", "Bearer xyz")
			.havingHeaderEqualTo("Accept", CommonContentTypes.APPLICATION_JSON.toString())
			.havingPathEqualTo("/path")
			.havingQueryStringEqualTo("apples=10&pears=20")
			.respond()
			.withStatus(200)
			.withHeader("SID", "abc")
			.withHeader("X-App", "123")
			.withBody("[10, 20]")
			.withEncoding(Charset.forName("UTF-8"))
			.withContentType(CommonContentTypes.APPLICATION_JSON.toString());

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/path"));
		httpRequest.setQuery("apples=10&pears=20");
		httpRequest.setFragment("fragment");
		httpRequest.setAuthorization("Bearer xyz");
		httpRequest.setAccept(CommonContentTypes.APPLICATION_JSON.toString());

		HTTPResponse httpResponse = httpRequest.send();

		assertThat(httpResponse.getStatusCode()).isEqualTo(200);
		assertThat(httpResponse.getStatusMessage()).isEqualTo("OK");
		httpResponse.ensureContentType(CommonContentTypes.APPLICATION_JSON);
		assertThat(httpResponse.getHeaderValue("SID")).isEqualTo("abc");
		assertThat(httpResponse.getHeaderValue("X-App")).isEqualTo("123");

		JsonArray jsonArray = httpResponse.getContentAsJSONArray();
		assertThat(jsonArray.getJsonNumber(0).longValue()).isEqualTo(10L);
		assertThat(jsonArray.getJsonNumber(1).longValue()).isEqualTo(20L);
		assertThat(jsonArray).hasSize(2);
	}


	@Test
	public void testSendMultiValuedHeader()
		throws Exception {

		onRequest()
			.havingMethodEqualTo("GET")
			.havingPathEqualTo("/path")
			.respond()
			.withStatus(200)
			.withHeader("Set-Cookie", "cookie-1")
			.withHeader("Set-Cookie", "cookie-2")
			.withBody("Hello, world!")
			.withEncoding(Charset.forName("UTF-8"))
			.withContentType("text/plain");

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URL("http://localhost:" + port() + "/path"));

		HTTPResponse httpResponse = httpRequest.send();

		assertThat(httpResponse.getStatusCode()).isEqualTo(200);
		assertThat(httpResponse.getStatusMessage()).isEqualTo("OK");
		assertThat(new HashSet<>(httpResponse.getHeaderValues("Set-Cookie"))).isEqualTo(new HashSet<>(Arrays.asList("cookie-1", "cookie-2")));
		httpResponse.ensureContentType(new ContentType("text/plain"));
		assertThat(httpResponse.getContent()).isEqualTo("Hello, world!\n");
	}
	
	
	@Test
	public void testWithClientCertificate()
		throws Exception {
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
		RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
		
		X509Certificate cert = X509CertificateGenerator.generateSelfSignedCertificate(
			new Issuer("123"),
			rsaPublicKey,
			rsaPrivateKey);
		
		cert.checkValidity();
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		
		assertThat(httpRequest.getClientX509Certificate()).isNull();
		
		httpRequest.setClientX509Certificate(cert);
		
		assertThat(httpRequest.getClientX509Certificate()).isEqualTo(cert);
	}
	
	
	@Test
	public void testGetAndSetDefaultHostnameVerifier() {
		
		HostnameVerifier mockHostnameVerifier = new HostnameVerifier() {
			@Override
			public boolean verify(String s, SSLSession sslSession) {
				return false;
			}
		};
		
		HostnameVerifier defaultHostnameVerifier = HTTPRequest.getDefaultHostnameVerifier();
		
		assertThat(defaultHostnameVerifier).isNotNull();
		
		HTTPRequest.setDefaultHostnameVerifier(mockHostnameVerifier);
		
		assertThat(HTTPRequest.getDefaultHostnameVerifier()).isEqualTo(mockHostnameVerifier);
	}
	
	
	@Test
	public void testRejectNullDefaultHostnameVerifier() {
		
		try {
			HTTPRequest.setDefaultHostnameVerifier(null);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The hostname verifier must not be null");
		}
	}
	
	
	@Test
	public void testRejectNullDefaultSSLSocketFactory() {
		
		try {
			HTTPRequest.setDefaultSSLSocketFactory(null);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The SSL socket factory must not be null");
		}
	}
	
	
	@Test
	public void testGetAndSetSubjectDN()
		throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		
		assertThat(httpRequest.getClientX509CertificateSubjectDN()).isNull();
		httpRequest.setClientX509CertificateSubjectDN("cn=subject");
		assertThat(httpRequest.getClientX509CertificateSubjectDN()).isEqualTo("cn=subject");
	}
	
	
	@Test
	public void testGetAndSetRootDN()
		throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		
		assertThat(httpRequest.getClientX509CertificateRootDN()).isNull();
		httpRequest.setClientX509CertificateRootDN("cn=root");
		assertThat(httpRequest.getClientX509CertificateRootDN()).isEqualTo("cn=root");
	}
	
	
	@Test
	public void testClientIP()
		throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		
		assertThat(httpRequest.getClientIPAddress()).isNull();
		
		String ip = "192.168.0.1";
		httpRequest.setClientIPAddress(ip);
		assertThat(httpRequest.getClientIPAddress()).isEqualTo(ip);
	}
	
	
	@Test
	public void testMultivaluedHeader()
		throws MalformedURLException {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		
		List<String> headerValues = Arrays.asList("V1", "V2");
		
		httpRequest.setHeader("X-Header", "V1", "V2");
		
		assertThat(httpRequest.getHeaderValues("X-Header")).isEqualTo(headerValues);
		
		assertThat(httpRequest.getHeaderValue("X-Header")).isEqualTo("V1");
	}
}
