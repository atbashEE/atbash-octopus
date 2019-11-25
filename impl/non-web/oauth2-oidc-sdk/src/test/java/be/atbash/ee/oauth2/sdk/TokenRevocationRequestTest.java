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


import be.atbash.ee.oauth2.sdk.auth.ClientAuthentication;
import be.atbash.ee.oauth2.sdk.auth.ClientSecretBasic;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.token.AccessToken;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.oauth2.sdk.token.RefreshToken;
import be.atbash.ee.oauth2.sdk.token.Token;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the token revocation request.
 */
public class TokenRevocationRequestTest {

	@Test
	public void testWithAccessToken_publicClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new BearerAccessToken();

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, new ClientID("123"), token);
		assertThat(request.getEndpointURI()).isEqualTo(endpointURI);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
		assertThat(request.getToken()).isEqualTo(token);

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getURL().toString()).isEqualTo(endpointURI.toURL().toString());
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
		assertThat(httpRequest.getAuthorization()).isNull();

		assertThat(httpRequest.getQueryParameters().get("token")).isEqualTo(Collections.singletonList(token.getValue()));
		assertThat(httpRequest.getQueryParameters().get("token_type_hint")).isEqualTo(Collections.singletonList("access_token"));
		assertThat(httpRequest.getQueryParameters().get("client_id")).isEqualTo(Collections.singletonList("123"));
		assertThat(httpRequest.getQueryParameters()).hasSize(3);

		request = TokenRevocationRequest.parse(httpRequest);
		assertThat(request.getEndpointURI()).isEqualTo(endpointURI);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
		assertThat(request.getToken().getValue()).isEqualTo(token.getValue());
		assertThat(request.getToken()).isInstanceOf(AccessToken.class);
	}

	@Test
	public void testWithAccessToken_confidentialClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new BearerAccessToken();
		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, clientAuth, token);
		assertThat(request.getEndpointURI()).isEqualTo(endpointURI);
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getToken()).isEqualTo(token);

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getURL().toString()).isEqualTo(endpointURI.toURL().toString());
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());

		assertThat(httpRequest.getQueryParameters().get("token")).isEqualTo(Collections.singletonList(token.getValue()));
		assertThat(httpRequest.getQueryParameters().get("token_type_hint")).isEqualTo(Collections.singletonList("access_token"));
		assertThat(httpRequest.getQueryParameters()).hasSize(2);

		ClientSecretBasic basicAuth = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertThat(basicAuth.getClientID().getValue()).isEqualTo("123");
		assertThat(basicAuth.getClientSecret().getValue()).isEqualTo("secret");

		request = TokenRevocationRequest.parse(httpRequest);
		assertThat(request.getEndpointURI()).isEqualTo(endpointURI);
		assertThat(request.getClientAuthentication().getClientID()).isEqualTo(clientAuth.getClientID());
		assertThat(((ClientSecretBasic)request.getClientAuthentication()).getClientSecret()).isEqualTo(clientAuth.getClientSecret());
		assertThat(request.getClientID()).isNull();
		assertThat(request.getToken().getValue()).isEqualTo(token.getValue());
		assertThat(request.getToken()).isInstanceOf(AccessToken.class);
	}

	@Test
	public void testWithRefreshToken_publicClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new RefreshToken();

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, new ClientID("123"), token);
		assertThat(request.getEndpointURI()).isEqualTo(endpointURI);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getToken()).isEqualTo(token);

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getURL().toString()).isEqualTo(endpointURI.toURL().toString());
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
		assertThat(httpRequest.getAuthorization()).isNull();

		assertThat(httpRequest.getQueryParameters().get("token")).isEqualTo(Collections.singletonList(token.getValue()));
		assertThat(httpRequest.getQueryParameters().get("token_type_hint")).isEqualTo(Collections.singletonList("refresh_token"));
		assertThat(httpRequest.getQueryParameters().get("client_id")).isEqualTo(Collections.singletonList("123"));
		assertThat(httpRequest.getQueryParameters()).hasSize(3);

		request = TokenRevocationRequest.parse(httpRequest);
		assertThat(request.getEndpointURI()).isEqualTo(endpointURI);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
		assertThat(request.getToken().getValue()).isEqualTo(token.getValue());
		assertThat(request.getToken()).isInstanceOf(RefreshToken.class);
	}

	@Test
	public void testWithRefreshToken_confidentialClient()
		throws Exception {

		URI endpointURI = new URI("https://c2id.com/token/revoke");
		Token token = new RefreshToken();
		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));

		TokenRevocationRequest request = new TokenRevocationRequest(endpointURI, clientAuth, token);
		assertThat(request.getEndpointURI()).isEqualTo(endpointURI);
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getToken()).isEqualTo(token);

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getURL().toString()).isEqualTo(endpointURI.toURL().toString());
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());

		assertThat(httpRequest.getQueryParameters().get("token")).isEqualTo(Collections.singletonList(token.getValue()));
		assertThat(httpRequest.getQueryParameters().get("token_type_hint")).isEqualTo(Collections.singletonList("refresh_token"));
		assertThat(httpRequest.getQueryParameters()).hasSize(2);

		ClientSecretBasic basicAuth = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertThat(basicAuth.getClientID().getValue()).isEqualTo("123");
		assertThat(basicAuth.getClientSecret().getValue()).isEqualTo("secret");

		request = TokenRevocationRequest.parse(httpRequest);
		assertThat(request.getEndpointURI()).isEqualTo(endpointURI);
		assertThat(request.getClientAuthentication().getClientID()).isEqualTo(clientAuth.getClientID());
		assertThat(((ClientSecretBasic)request.getClientAuthentication()).getClientSecret()).isEqualTo(clientAuth.getClientSecret());
		assertThat(request.getClientID()).isNull();
		assertThat(request.getToken().getValue()).isEqualTo(token.getValue());
		assertThat(request.getToken()).isInstanceOf(RefreshToken.class);
	}

	@Test
	public void testWithUnknownToken_publicClient()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		Map<String, List<String>> queryParams = new HashMap<>();
		queryParams.put("token", Collections.singletonList("abc"));
		queryParams.put("client_id", Collections.singletonList("123"));
		httpRequest.setQuery(URLUtils.serializeParameters(queryParams));

		TokenRevocationRequest request = TokenRevocationRequest.parse(httpRequest);
		assertThat(request.getToken().getValue()).isEqualTo("abc");
		assertThat(request.getToken()).isNotInstanceOf(AccessToken.class);
		assertThat(request.getToken()).isNotInstanceOf(RefreshToken.class);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
	}

	@Test
	public void testWithUnknownToken_confidentialClient()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setAuthorization(new ClientSecretBasic(new ClientID("123"), new Secret("secret")).toHTTPAuthorizationHeader());
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		Map<String, List<String>> queryParams = new HashMap<>();
		queryParams.put("token", Collections.singletonList("abc"));
		httpRequest.setQuery(URLUtils.serializeParameters(queryParams));

		TokenRevocationRequest request = TokenRevocationRequest.parse(httpRequest);
		assertThat(request.getToken().getValue()).isEqualTo("abc");
		assertThat(request.getToken()).isNotInstanceOf(AccessToken.class);
		assertThat(request.getToken()).isNotInstanceOf(RefreshToken.class);
		assertThat(request.getClientAuthentication().getClientID()).isEqualTo(new ClientID("123"));
		assertThat(((ClientSecretBasic)request.getClientAuthentication()).getClientSecret()).isEqualTo(new Secret("secret"));
		assertThat(request.getClientID()).isNull();
	}

	@Test
	public void testConstructorRequireClientAuthentication() {

		try {
			new TokenRevocationRequest(URI.create("https://c2id.com/token"), (ClientAuthentication)null, new BearerAccessToken());
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The client authentication must not be null");
		}
	}

	@Test
	public void testConstructorRequireClientID() {

		try {
			new TokenRevocationRequest(URI.create("https://c2id.com/token"), (ClientID) null, new BearerAccessToken());
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The client ID must not be null");
		}
	}

	@Test
	public void testParseMissingClientIdentification()
		throws MalformedURLException {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token/revoke"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		Map<String, List<String>> queryParams = new HashMap<>();
		queryParams.put("token", Collections.singletonList("abc"));
		httpRequest.setQuery(URLUtils.serializeParameters(queryParams));

		try {
			TokenRevocationRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Invalid token revocation request: No client authentication or client_id parameter found");
		}
	}
}
