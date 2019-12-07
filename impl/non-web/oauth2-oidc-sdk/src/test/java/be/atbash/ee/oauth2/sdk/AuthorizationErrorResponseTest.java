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
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests authorisation error response serialisation and parsing.
 */
public class AuthorizationErrorResponseTest  {
	
	
	private static URI REDIRECT_URI = null;
	
	
	private static URI ERROR_PAGE_URL = null;
	
	@Before
	public void setUp()
		throws URISyntaxException {
		
		REDIRECT_URI = new URI("https://client.example.com/cb");
		
		ERROR_PAGE_URL = new URI("http://server.example.com/error/123");
	}

	@Test
	public void testStandardErrors() {
	
		Set<ErrorObject> errors = AuthorizationErrorResponse.getStandardErrors();
	
		assertThat(errors).contains(OAuth2Error.INVALID_REQUEST);
		assertThat(errors).contains(OAuth2Error.UNAUTHORIZED_CLIENT);
		assertThat(errors).contains(OAuth2Error.ACCESS_DENIED);
		assertThat(errors).contains(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE);
		assertThat(errors).contains(OAuth2Error.INVALID_SCOPE);
		assertThat(errors).contains(OAuth2Error.SERVER_ERROR);
		assertThat(errors).contains(OAuth2Error.TEMPORARILY_UNAVAILABLE);
		
		assertThat(errors).hasSize(7);
	}

	@Test
	public void testSerializeAndParse()
		throws Exception {
	
		State state = new State("xyz");
	
		AuthorizationErrorResponse r = new AuthorizationErrorResponse(
			REDIRECT_URI,
			OAuth2Error.INVALID_REQUEST,
			state,
			ResponseMode.QUERY);

		assertThat(r.indicatesSuccess()).isFalse();
		assertThat(r.getRedirectionURI()).isEqualTo(REDIRECT_URI);
		assertThat(r.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
		assertThat(r.getResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(r.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);

		assertThat(r.getState()).isEqualTo(state);

		Map<String, List<String>> params = r.toParameters();
		assertThat(params.get("error")).isEqualTo(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getCode()));
		assertThat(params.get("error_description")).isEqualTo(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getDescription()));
		assertThat(params.get("error_uri")).isNull();
		assertThat(params.get("state")).isEqualTo(Collections.singletonList(state.toString()));
		assertThat(params).hasSize(3);

		URI location = r.toURI();
			
		assertThat(location.getFragment()).isNull();
		assertThat(location.getQuery()).isNotNull();
			
		assertThat(location.getScheme()).isEqualTo(REDIRECT_URI.getScheme());
		assertThat(location.getPort()).isEqualTo(REDIRECT_URI.getPort());
		assertThat(location.getHost()).isEqualTo(REDIRECT_URI.getHost());
		assertThat(location.getPath()).isEqualTo(REDIRECT_URI.getPath());
			
		params = URLUtils.parseParameters(location.getQuery());
			
		assertThat(params.get("error")).isEqualTo(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getCode()));
		assertThat(params.get("error_description")).isEqualTo(Collections.singletonList(OAuth2Error.INVALID_REQUEST.getDescription()));
		assertThat(params.get("state")).isEqualTo(Collections.singletonList(state.toString()));
		assertThat(params).hasSize(3);
			
		HTTPResponse httpResponse = r.toHTTPResponse();
			
		assertThat(httpResponse.getStatusCode()).isEqualTo(HTTPResponse.SC_FOUND);
		assertThat(httpResponse.getLocation()).isEqualTo(location);

		r = AuthorizationErrorResponse.parse(httpResponse);

		assertThat(r.indicatesSuccess()).isFalse();
		assertThat(r.getRedirectionURI()).isEqualTo(REDIRECT_URI);
		assertThat(r.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
		assertThat(r.getResponseMode()).isNull();
		assertThat(r.impliedResponseMode()).isEqualTo(ResponseMode.QUERY); // default
		assertThat(r.getState()).isEqualTo(state);
	}

	@Test
	public void testCodeErrorInQueryString()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		State state = new State();

		AuthorizationErrorResponse response = new AuthorizationErrorResponse(
			redirectURI, error, state, ResponseMode.QUERY);

		assertThat(response.indicatesSuccess()).isFalse();
		assertThat(response.getRedirectionURI()).isEqualTo(redirectURI);
		assertThat(response.getErrorObject()).isEqualTo(error);
		assertThat(response.getResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(response.getState()).isEqualTo(state);

		URI responseURI = response.toURI();

		assertThat(responseURI.getQuery()).isNotNull();
		assertThat(responseURI.getFragment()).isNull();

		response = AuthorizationErrorResponse.parse(responseURI);

		assertThat(response.indicatesSuccess()).isFalse();
		assertThat(response.getRedirectionURI()).isEqualTo(redirectURI);
		assertThat(response.getErrorObject()).isEqualTo(error);
		assertThat(response.getResponseMode()).isNull();
		assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.QUERY); // default
		assertThat(response.getState()).isEqualTo(state);
	}

	@Test
	public void testErrorInFragment()
		throws Exception {

		URI redirectURI = new URI("https://client.com/cb");
		ErrorObject error = OAuth2Error.ACCESS_DENIED;
		State state = new State();

		AuthorizationErrorResponse response = new AuthorizationErrorResponse(
			redirectURI, error, state, ResponseMode.FRAGMENT);

		assertThat(response.indicatesSuccess()).isFalse();
		assertThat(response.getRedirectionURI()).isEqualTo(redirectURI);
		assertThat(response.getErrorObject()).isEqualTo(error);
		assertThat(response.getResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(response.getState()).isEqualTo(state);

		URI responseURI = response.toURI();

		assertThat(responseURI.getQuery()).isNull();
		assertThat(responseURI.getFragment()).isNotNull();

		response = AuthorizationErrorResponse.parse(responseURI);

		assertThat(response.indicatesSuccess()).isFalse();
		assertThat(response.getRedirectionURI()).isEqualTo(redirectURI);
		assertThat(response.getErrorObject()).isEqualTo(error);
		assertThat(response.getResponseMode()).isNull();
		assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.QUERY); // default
		assertThat(response.getState()).isEqualTo(state);
	}

	@Test
	public void testParse()
		throws URISyntaxException {
	
		String s = "https://client.example.com/cb?error=invalid_request&error_description=Invalid+request&error_uri=http%3A%2F%2Fserver.example.com%2Ferror%2F123&state=123";

		AuthorizationErrorResponse r = null;
		
		try {
			r = AuthorizationErrorResponse.parse(new URI(s));
			
		} catch (OAuth2JSONParseException e) {
		
			fail(e.getMessage());
		}

		assertThat(r.indicatesSuccess()).isFalse();
		assertThat(r.getRedirectionURI().toString()).isEqualTo("https://client.example.com/cb");
		assertThat(r.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
		assertThat(r.getErrorObject().getURI()).isEqualTo(ERROR_PAGE_URL);
		assertThat(r.getState()).isEqualTo(new State("123"));
		
		assertThat(r.getResponseMode()).isNull();
		assertThat(r.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
	}

	@Test
	public void testParseExceptions()
		throws URISyntaxException {
		
		String s1 = "https://client.example.com/cb";
		
		try {
			AuthorizationErrorResponse.parse(new URI(s1));
			fail();
			
		} catch (OAuth2JSONParseException e) {
			// ok
		}
	}

	@Test
	public void testRedirectionURIWithQueryString()
		throws Exception {
		// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/140

		URI redirectURI = URI.create("https://example.com/myservice/?action=oidccallback");
		assertThat(redirectURI.getQuery()).isEqualTo("action=oidccallback");

		State state = new State();

		ErrorObject error = OAuth2Error.ACCESS_DENIED;

		AuthorizationErrorResponse response = new AuthorizationErrorResponse(redirectURI, error, state, ResponseMode.QUERY);

		Map<String, List<String>> params = response.toParameters();
		assertThat(params.get("error")).isEqualTo(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getCode()));
		assertThat(params.get("error_description")).isEqualTo(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getDescription()));
		assertThat(params.get("state")).isEqualTo(Collections.singletonList(state.getValue()));
		assertThat(params).hasSize(3);

		URI uri = response.toURI();

		params = URLUtils.parseParameters(uri.getQuery());
		assertThat(params.get("action")).isEqualTo(Collections.singletonList("oidccallback"));
		assertThat(params.get("error")).isEqualTo(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getCode()));
		assertThat(params.get("error_description")).isEqualTo(Collections.singletonList(OAuth2Error.ACCESS_DENIED.getDescription()));
		assertThat(params.get("state")).isEqualTo(Collections.singletonList(state.getValue()));
		assertThat(params).hasSize(4);
	}
}
