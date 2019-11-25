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


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.Test;

import javax.json.JsonArray;
import javax.json.JsonObject;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the HTTP response class.
 */
public class HTTPResponseTest  {

	@Test
	public void testConstructorAndAccessors()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);

		assertThat(response.indicatesSuccess()).isTrue();
		assertThat(response.getStatusCode()).isEqualTo(200);

		response.ensureStatusCode(200);
		response.ensureStatusCode(200, 201);

		try {
			response.ensureStatusCode(302);
			fail();
		} catch (OAuth2JSONParseException e) {
			// ok
			assertThat(e.getMessage()).isEqualTo("Unexpected HTTP status code 200, must be [302]");
		}
		
		assertThat(response.getStatusMessage()).isNull();
		response.setStatusMessage("OK");
		assertThat(response.getStatusMessage()).isEqualTo("OK");

		assertThat(response.getContentType()).isNull();
		response.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		assertThat(response.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());

		assertThat(response.getLocation()).isNull();
		URI location = new URI("https://client.com/cb");
		response.setLocation(location);
		assertThat(response.getLocation()).isEqualTo(location);

		assertThat(response.getCacheControl()).isNull();
		response.setCacheControl("no-cache");
		assertThat(response.getCacheControl()).isEqualTo("no-cache");

		assertThat(response.getPragma()).isNull();
		response.setPragma("no-cache");
		assertThat(response.getPragma()).isEqualTo("no-cache");

		assertThat(response.getWWWAuthenticate()).isNull();
		response.setWWWAuthenticate("Basic");
		assertThat(response.getWWWAuthenticate()).isEqualTo("Basic");

		assertThat(response.getContent()).isNull();

		try {
			response.getContentAsJSONObject();
			fail();
		} catch (OAuth2JSONParseException e) {
			// ok
		}

		try {
			response.getContentAsJWT();
			fail();
		} catch (OAuth2JSONParseException e) {
			// ok
		}

		response.setContentType(CommonContentTypes.APPLICATION_JSON);
		response.setContent("{\"apples\":\"123\"}");
		assertThat(response.getContent()).isEqualTo("{\"apples\":\"123\"}");

		JsonObject jsonObject = response.getContentAsJSONObject();
		assertThat(jsonObject.getString("apples")).isEqualTo("123");

		// From http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-13#section-3.1
		String exampleJWTString = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
			"." +
			"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
			"cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
			"." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

		response.setContentType(CommonContentTypes.APPLICATION_JWT);
		response.setContent(exampleJWTString);

		JWT jwt = response.getContentAsJWT();
		assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
	}

	@Test
	public void testGetContentAsJSONArray()
		throws Exception {

		HTTPResponse response = new HTTPResponse(200);
		response.setContentType(CommonContentTypes.APPLICATION_JSON);
		response.setContent("[\"apples\",\"pears\"]");

		JsonArray array = response.getContentAsJSONArray();
		assertThat(array.getString(0)).isEqualTo("apples");
		assertThat(array.getString(1)).isEqualTo("pears");
		assertThat(array).hasSize(2);
	}

	@Test
	public void testPreserveHeaderCase() {
		HTTPResponse response = new HTTPResponse(302);
		response.setHeader("Location", "http://example.org");

		assertThat(response.getHeaderMap().keySet().iterator().next()).isEqualTo("Location");
	}

	@Test
	public void testGetHeaderWithCaseMismatch()
		throws URISyntaxException {

		HTTPResponse response = new HTTPResponse(302);
		response.setHeader("location", "http://example.org");

		assertThat(response.getLocation()).isEqualTo(new URI("http://example.org"));
	}

	@Test
	public void testRemoveHeaderWithCaseMismatch()
		throws URISyntaxException {

		HTTPResponse response = new HTTPResponse(302);
		response.setHeader("location", "http://example.org");

		assertThat(response.getLocation()).isEqualTo(new URI("http://example.org"));

		response.setHeader("LOCATION", null);

		assertThat(response.getLocation()).isNull();
	}

	@Test
	public void testClientIP()
		throws MalformedURLException {
		
		HTTPResponse httpResponse = new HTTPResponse(200);
		
		assertThat(httpResponse.getClientIPAddress()).isNull();
		
		String ip = "192.168.0.1";
		httpResponse.setClientIPAddress(ip);
		assertThat(httpResponse.getClientIPAddress()).isEqualTo(ip);
	}
}
