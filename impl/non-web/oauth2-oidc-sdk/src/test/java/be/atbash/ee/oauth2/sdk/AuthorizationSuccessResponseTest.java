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
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.token.AccessToken;
import be.atbash.ee.oauth2.sdk.token.AccessTokenType;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests authorisation response serialisation and parsing.
 */
public class AuthorizationSuccessResponseTest {
	
	
	private static URI ABS_REDIRECT_URI = null;


	private static AuthorizationCode CODE = new AuthorizationCode("SplxlOBeZQQYbYS6WxSbIA");


	private static AccessToken TOKEN = new BearerAccessToken("2YotnFZFEjr1zCsicMWpAA", 3600, null);


	private static State STATE = new State("xyz");


	private static String RESPONSE_CODE =
		"https://client.example.org/cb?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz";


	private static String RESPONSE_TOKEN =
		"https://client.example.org/cb#" +
		"&access_token=2YotnFZFEjr1zCsicMWpAA" +
		"&token_type=Bearer" +
		"&expires_in=3600" +
		"&state=xyz";
	
	@Before
	public void setUp()
		throws URISyntaxException,
		       java.text.ParseException {
		
		ABS_REDIRECT_URI = new URI("https://client.example.org/cb");
	}
	
	@Test
	public void testCodeFlow()
		throws Exception {
	
		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(ABS_REDIRECT_URI, CODE, null, STATE, null);

		assertThat(resp.indicatesSuccess()).isTrue();
		assertThat(resp.getRedirectionURI()).isEqualTo(ABS_REDIRECT_URI);
		assertThat(resp.getAuthorizationCode()).isEqualTo(CODE);
		assertThat(resp.getState()).isEqualTo(STATE);
		assertThat(resp.getAccessToken()).isNull();
		assertThat(resp.getResponseMode()).isNull();

		assertThat(resp.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);

		Map<String, List<String>> params = resp.toParameters();
		assertThat(new AuthorizationCode(MultivaluedMapUtils.getFirstValue(params, "code"))).isEqualTo(CODE);
		assertThat(new State(MultivaluedMapUtils.getFirstValue(params,"state"))).isEqualTo(STATE);
		assertThat(params).hasSize(2);

		URI uri = resp.toURI();

		HTTPResponse httpResponse = resp.toHTTPResponse();
		assertThat(httpResponse.getStatusCode()).isEqualTo(302);
		assertThat(httpResponse.getLocation().toString()).isEqualTo(uri.toString());

	}

	@Test
	public void testImplicitFlow()
		throws Exception {
	
		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(ABS_REDIRECT_URI, null, TOKEN, STATE, null);

		assertThat(resp.indicatesSuccess()).isTrue();
		assertThat(resp.getRedirectionURI()).isEqualTo(ABS_REDIRECT_URI);
		assertThat(resp.getAccessToken()).isEqualTo(TOKEN);
		assertThat(resp.getAccessToken().getLifetime()).isEqualTo(3600);
		assertThat(resp.getState()).isEqualTo(STATE);
		assertThat(resp.getAuthorizationCode()).isNull();
		assertThat(resp.getResponseMode()).isNull();

		assertThat(resp.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);

		Map<String, List<String>> params = resp.toParameters();
		assertThat(MultivaluedMapUtils.getFirstValue(params,"access_token")).isEqualTo(TOKEN.getValue());
		assertThat(new State(MultivaluedMapUtils.getFirstValue(params, "state"))).isEqualTo(STATE);
		assertThat(new AccessTokenType(MultivaluedMapUtils.getFirstValue(params,"token_type"))).isEqualTo(TOKEN.getType());
		assertThat(MultivaluedMapUtils.getFirstValue(params, "expires_in")).isEqualTo("3600");
		assertThat(params).hasSize(4);

		URI uri = resp.toURI();


		HTTPResponse httpResponse = resp.toHTTPResponse();
		assertThat(httpResponse.getStatusCode()).isEqualTo(302);
		assertThat(httpResponse.getLocation()).isEqualTo(uri);

	}

	@Test
	public void testResponseModeFormPost()
		throws Exception {

		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(
			ABS_REDIRECT_URI,
			null,
			TOKEN,
			STATE,
			ResponseMode.FORM_POST);

		assertThat(resp.getResponseMode()).isEqualTo(ResponseMode.FORM_POST);
		assertThat(resp.impliedResponseMode()).isEqualTo(ResponseMode.FORM_POST);

		try {
			resp.toURI();
			fail();
		} catch (SerializeException e) {
			// ok
		}

		HTTPRequest httpRequest = resp.toHTTPRequest();
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
		assertThat(httpRequest.getURL().toURI()).isEqualTo(ABS_REDIRECT_URI);

		assertThat(httpRequest.getQueryParameters().get("token_type")).isEqualTo(Collections.singletonList("Bearer"));
		assertThat(httpRequest.getQueryParameters().get("expires_in")).isEqualTo(Collections.singletonList(TOKEN.getLifetime() + ""));
		assertThat(httpRequest.getQueryParameters().get("access_token")).isEqualTo(Collections.singletonList(TOKEN.getValue()));
		assertThat(httpRequest.getQueryParameters().get("state")).isEqualTo(Collections.singletonList(STATE.getValue()));
		assertThat(httpRequest.getQueryParameters()).hasSize(4);
	}

	@Test
	public void testOverrideQueryResponseMode()
		throws Exception {

		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(
			ABS_REDIRECT_URI,
			CODE,
			null,
			STATE,
			ResponseMode.FRAGMENT);

		assertThat(resp.getResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(resp.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);

		try {
			resp.toHTTPRequest();
			fail();
		} catch (SerializeException e) {
			// ok
		}

		URI uri = resp.toURI();
		assertThat(uri.getQuery()).isNull();
		Map<String, List<String>> params = URLUtils.parseParameters(uri.getRawFragment());
		assertThat(MultivaluedMapUtils.getFirstValue(params, "code")).isEqualTo(CODE.getValue());
		assertThat(MultivaluedMapUtils.getFirstValue(params, "state")).isEqualTo(STATE.getValue());
		assertThat(params).hasSize(2);
	}

	@Test
	public void testOverrideFragmentResponseMode()
		throws Exception {

		AuthorizationSuccessResponse resp = new AuthorizationSuccessResponse(
			ABS_REDIRECT_URI,
			null,
			TOKEN,
			STATE,
			ResponseMode.QUERY);

		assertThat(resp.getResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(resp.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);

		try {
			resp.toHTTPRequest();
			fail();
		} catch (SerializeException e) {
			// ok
		}

		URI uri = resp.toURI();
		assertThat(uri.getRawFragment()).isNull();
		Map<String, List<String>> params = URLUtils.parseParameters(uri.getQuery());
		assertThat(MultivaluedMapUtils.getFirstValue(params, "token_type")).isEqualTo("Bearer");
		assertThat(MultivaluedMapUtils.getFirstValue(params, "access_token")).isEqualTo(TOKEN.getValue());
		assertThat(MultivaluedMapUtils.getFirstValue(params, "expires_in")).isEqualTo(TOKEN.getLifetime() + "");
		assertThat(MultivaluedMapUtils.getFirstValue(params, "state")).isEqualTo(STATE.getValue());
		assertThat(params).hasSize(4);
	}

	@Test
	public void testRedirectionURIWithQueryString()
		throws Exception {
		// See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/140

		URI redirectURI = URI.create("https://example.com/myservice/?action=oidccallback");
		assertThat(redirectURI.getQuery()).isEqualTo("action=oidccallback");

		AuthorizationCode code = new AuthorizationCode();
		State state = new State();

		AuthorizationSuccessResponse response = new AuthorizationSuccessResponse(redirectURI, code, null, state, ResponseMode.QUERY);

		Map<String, List<String>> params = response.toParameters();
		assertThat(MultivaluedMapUtils.getFirstValue(params, "code")).isEqualTo(code.getValue());
		assertThat(MultivaluedMapUtils.getFirstValue(params, "state")).isEqualTo(state.getValue());
		assertThat(params).hasSize(2);

		URI uri = response.toURI();

		params = URLUtils.parseParameters(uri.getQuery());
		assertThat(MultivaluedMapUtils.getFirstValue(params, "action")).isEqualTo("oidccallback");
		assertThat(MultivaluedMapUtils.getFirstValue(params, "code")).isEqualTo(code.getValue());
		assertThat(MultivaluedMapUtils.getFirstValue(params, "state")).isEqualTo(state.getValue());
		assertThat(params).hasSize(3);
	}


}
