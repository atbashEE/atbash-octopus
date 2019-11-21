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


import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class PushedAuthorizationSuccessResponseTest  {
	
	@Test
	public void testLifeCycle() throws OAuth2JSONParseException{
		
		// https://tools.ietf.org/html/rfc6755
		URI requestURI = URI.create("urn:ietf:params:oauth:request_uri:tioteej8");
		long lifetime = 3600L;
		
		PushedAuthorizationSuccessResponse response = new PushedAuthorizationSuccessResponse(requestURI, lifetime);
		assertThat(response.getRequestURI()).isEqualTo(requestURI);
		assertThat(response.getLifetime()).isEqualTo(lifetime);
		assertThat(response.indicatesSuccess()).isTrue();
		
		JsonObject jsonObject = response.toJSONObject();
		assertThat(jsonObject.getString("request_uri")).isEqualTo(requestURI.toString());
		assertThat(jsonObject.getJsonNumber("expires_in").longValue()).isEqualTo(lifetime);
		assertThat(jsonObject).hasSize(2);
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertThat(httpResponse.getStatusCode()).isEqualTo(201);
		assertThat(httpResponse.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_JSON.toString());
		jsonObject = response.toJSONObject();
		assertThat(jsonObject.getString("request_uri")).isEqualTo(requestURI.toString());
		assertThat(jsonObject.getJsonNumber("expires_in").longValue()).isEqualTo(lifetime);
		assertThat(jsonObject).hasSize(2);
		
		response = PushedAuthorizationSuccessResponse.parse(jsonObject);
		assertThat(response.getRequestURI()).isEqualTo(requestURI);
		assertThat(response.getLifetime()).isEqualTo(lifetime);
	}

	@Test
	public void testRejectNullRequestURI() {
		
		try {
			new PushedAuthorizationSuccessResponse(null, 3600);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The request URI must not be null");
		}
	}

	@Test
	public void testRejectNonPositiveLifetime() {
		
		try {
			new PushedAuthorizationSuccessResponse(URI.create("urn:ietf:params:oauth:request_uri:tioteej8"), 0L);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The request lifetime must be a positive integer");
		}
		
		try {
			new PushedAuthorizationSuccessResponse(URI.create("urn:ietf:params:oauth:request_uri:tioteej8"), -1L);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The request lifetime must be a positive integer");
		}
	}

	@Test
	public void testParse_missingRequestURI() {
		
		JsonObjectBuilder jsonObject = Json.createObjectBuilder();
		jsonObject.add("expires_in", 3600L);
		try {
			PushedAuthorizationSuccessResponse.parse(jsonObject.build());
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing JSON object member with key \"request_uri\"");
		}
	}

	@Test
	public void testParse_missingLifetime() {
		
		JsonObjectBuilder jsonObject = Json.createObjectBuilder();
		jsonObject.add("request_uri", "urn:ietf:params:oauth:request_uri:tioteej8");
		try {
			PushedAuthorizationSuccessResponse.parse(jsonObject.build());
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing JSON object member with key \"expires_in\"");
		}
	}
}
