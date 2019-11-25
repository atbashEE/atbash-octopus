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



import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class RequestObjectPOSTSuccessResponseTest {

	@Test
	public void testLifeCycle() throws OAuth2JSONParseException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);
		
		assertThat(response.getIssuer()).isEqualTo(issuer);
		assertThat(response.getAudience()).isEqualTo(audience);
		assertThat(response.getRequestURI()).isEqualTo(requestURI);
		assertThat(response.getExpirationTime()).isEqualTo(exp);
		
		assertThat(response.indicatesSuccess()).isTrue();
		
		JsonObject jsonObject = response.toJSONObject();
		assertThat(jsonObject.getString("iss")).isEqualTo(issuer.getValue());
		assertThat(jsonObject.getString("aud")).isEqualTo(audience.getValue());
		assertThat(jsonObject.getString("request_uri")).isEqualTo(requestURI.toString());
		assertThat(jsonObject.getJsonNumber("exp").longValue()).isEqualTo(expTs);
		assertThat(jsonObject).hasSize(4);
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertThat(httpResponse.getStatusCode()).isEqualTo(201);
		assertThat(httpResponse.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_JSON.toString());
		
		jsonObject = httpResponse.getContentAsJSONObject();
		assertThat(jsonObject.getString("iss")).isEqualTo(issuer.getValue());
		assertThat(jsonObject.getString("aud")).isEqualTo(audience.getValue());
		assertThat(jsonObject.getString("request_uri")).isEqualTo(requestURI.toString());
		assertThat(jsonObject.getJsonNumber("exp").longValue()).isEqualTo(expTs);
		assertThat(jsonObject).hasSize(4);
		
		response = RequestObjectPOSTSuccessResponse.parse(jsonObject);
		
		assertThat(response.getIssuer()).isEqualTo(issuer);
		assertThat(response.getAudience()).isEqualTo(audience);
		assertThat(response.getRequestURI()).isEqualTo(requestURI);
		assertThat(response.getExpirationTime()).isEqualTo(exp);
		
		response = RequestObjectPOSTSuccessResponse.parse(httpResponse);
		
		assertThat(response.getIssuer()).isEqualTo(issuer);
		assertThat(response.getAudience()).isEqualTo(audience);
		assertThat(response.getRequestURI()).isEqualTo(requestURI);
		assertThat(response.getExpirationTime()).isEqualTo(exp);
	}

	@Test
	public void testRejectNullParams() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		try {
			new RequestObjectPOSTSuccessResponse(null, audience, requestURI, exp);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The issuer must not be null");
		}
		
		try {
			new RequestObjectPOSTSuccessResponse(issuer, null, requestURI, exp);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The audience must not be null");
		}
		
		try {
			new RequestObjectPOSTSuccessResponse(issuer, audience, null, exp);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The request URI must not be null");
		}
		
		try {
			new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The request URI expiration time must not be null");
		}
	}

	@Test
	public void testParseJSONObject_missingParams() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);
		
		JsonObject jsonObject = response.toJSONObject();

		JsonObjectBuilder builder = Json.createObjectBuilder(jsonObject);
		builder.remove("iss");
		jsonObject = builder.build();
		try {
			RequestObjectPOSTSuccessResponse.parse(jsonObject);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing JSON object member with key \"iss\"");
		}
		
		jsonObject = response.toJSONObject();
		jsonObject = JSONObjectUtils.remove(jsonObject, "aud");
		try {
			RequestObjectPOSTSuccessResponse.parse(jsonObject);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing JSON object member with key \"aud\"");
		}
		
		jsonObject = response.toJSONObject();
		jsonObject = JSONObjectUtils.remove(jsonObject, "request_uri");
		try {
			RequestObjectPOSTSuccessResponse.parse(jsonObject);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing JSON object member with key \"request_uri\"");
		}
		
		jsonObject = response.toJSONObject();
		jsonObject = JSONObjectUtils.remove(jsonObject, "exp");
		try {
			RequestObjectPOSTSuccessResponse.parse(jsonObject);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing JSON object member with key \"exp\"");
		}
	}

	@Test
	public void testParseHTTPResponse_unexpectedStatusCode() {
		
		try {
			RequestObjectPOSTSuccessResponse.parse(new HTTPResponse(HTTPResponse.SC_UNAUTHORIZED));
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Unexpected HTTP status code 401, must be [201, 200]");
		}
	}

	@Test
	public void testParseMissingContentTypeHeader() throws OAuth2JSONParseException {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);
		HTTPResponse httpResponse = response.toHTTPResponse();
		httpResponse.setContentType((String)null);
		
		try {
			RequestObjectPOSTSuccessResponse.parse(httpResponse);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing HTTP Content-Type header");
		}
	}

	@Test
	public void testParseInvalidJSON() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);
		HTTPResponse httpResponse = response.toHTTPResponse();
		httpResponse.setContent("text plain");
		
		try {
			RequestObjectPOSTSuccessResponse.parse(httpResponse);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Unexpected exception: Unexpected char 101 at (line no=1, column no=2, offset=1), expecting 'r'");
		}
	}

	@Test
	public void testParseMissingIssuer() {
		
		Issuer issuer = new Issuer("https://c2id.com");
		Audience audience = new Audience("123");
		URI requestURI = URI.create("urn:requests:aashoo1Ooj6ahc5C");
		long expTs = DateUtils.toSecondsSinceEpoch(new Date());
		Date exp = DateUtils.fromSecondsSinceEpoch(expTs);
		
		RequestObjectPOSTSuccessResponse response = new RequestObjectPOSTSuccessResponse(issuer, audience, requestURI, exp);
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		JsonObject jsonObject = response.toJSONObject();

		JsonObjectBuilder builder = Json.createObjectBuilder(jsonObject);
		builder.remove("iss");
		jsonObject = builder.build();
		httpResponse.setContent(jsonObject.toString());
		
		try {
			RequestObjectPOSTSuccessResponse.parse(httpResponse);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing JSON object member with key \"iss\"");
		}
	}
}
