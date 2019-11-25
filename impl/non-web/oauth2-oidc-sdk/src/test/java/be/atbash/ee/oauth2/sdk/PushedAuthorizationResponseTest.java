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



import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import org.junit.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;


public class PushedAuthorizationResponseTest  {
	
	@Test
	public void testParseSuccess() throws OAuth2JSONParseException {
		
		URI requestURI = URI.create("urn:ietf:params:oauth:request_uri:tioteej8");
		long lifetime = 3600L;
		
		PushedAuthorizationSuccessResponse response = new PushedAuthorizationSuccessResponse(requestURI, lifetime);
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertThat(httpResponse.getStatusCode()).isEqualTo(201);
		
		response = PushedAuthorizationResponse.parse(httpResponse).toSuccessResponse();
		assertThat(response.getRequestURI()).isEqualTo(requestURI);
		assertThat(response.getLifetime()).isEqualTo(lifetime);
	}
	
	// Be lenient on HTTP 200
	@Test
	public void testParseSuccess200() throws OAuth2JSONParseException {
		
		URI requestURI = URI.create("urn:ietf:params:oauth:request_uri:tioteej8");
		long lifetime = 3600L;
		
		PushedAuthorizationSuccessResponse response = new PushedAuthorizationSuccessResponse(requestURI, lifetime);
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		assertThat(httpResponse.getStatusCode()).isEqualTo(201);
		
		HTTPResponse modifiedHTTPResponse = new HTTPResponse(200);
		modifiedHTTPResponse.setContentType(httpResponse.getContentType());
		modifiedHTTPResponse.setContent(httpResponse.getContent());
		
		response = PushedAuthorizationResponse.parse(modifiedHTTPResponse).toSuccessResponse();
		assertThat(response.getRequestURI()).isEqualTo(requestURI);
		assertThat(response.getLifetime()).isEqualTo(lifetime);
	}

	@Test
	public void testParseError() throws OAuth2JSONParseException {
		
		PushedAuthorizationErrorResponse response = new PushedAuthorizationErrorResponse(new ErrorObject(null, null, 400));
		
		HTTPResponse httpResponse = response.toHTTPResponse();
		
		response = PushedAuthorizationResponse.parse(httpResponse).toErrorResponse();
		assertThat(response.indicatesSuccess()).isFalse();
		assertThat(response.getErrorObject().toParameters().isEmpty()).isTrue();
	}
}
