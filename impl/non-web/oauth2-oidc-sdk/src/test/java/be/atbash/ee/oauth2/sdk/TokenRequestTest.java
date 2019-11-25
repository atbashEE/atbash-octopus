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


import be.atbash.ee.oauth2.sdk.assertions.jwt.JWTAssertionDetails;
import be.atbash.ee.oauth2.sdk.assertions.jwt.JWTAssertionFactory;
import be.atbash.ee.oauth2.sdk.auth.*;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.oauth2.sdk.pkce.CodeVerifier;
import be.atbash.ee.oauth2.sdk.token.RefreshToken;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import org.junit.Test;

import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocketFactory;
import java.net.URI;
import java.net.URL;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class TokenRequestTest  {

	@Test
	public void testConstructorWithClientAuthentication()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);
		Scope scope = Scope.parse("openid email");

		TokenRequest request = new TokenRequest(uri, clientAuth, grant, scope);

		assertThat(request.getEndpointURI()).isEqualTo(uri);
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isEqualTo(scope);
		assertThat(request.getResources()).isNull();
		assertThat(request.getExistingGrant()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getURL()).isEqualTo(uri.toURL());
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertThat(basic.getClientID().getValue()).isEqualTo("123");
		assertThat(basic.getClientSecret().getValue()).isEqualTo("secret");
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
		assertThat(params.get("code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(Scope.parse(MultivaluedMapUtils.getFirstValue(params, "scope"))).isEqualTo(new Scope("openid", "email"));
		assertThat(params).hasSize(3);
	}

	@Test
	public void testFullConstructorWithClientAuthentication()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);
		Scope scope = Scope.parse("openid email");
		List<URI> resources = Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com"));
		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));

		TokenRequest request = new TokenRequest(uri, clientAuth, grant, scope, resources, customParams);

		assertThat(request.getEndpointURI()).isEqualTo(uri);
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isEqualTo(scope);
		assertThat(request.getResources()).isEqualTo(resources);
		assertThat(request.getExistingGrant()).isNull();
		assertThat(request.getCustomParameters()).isEqualTo(customParams);

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getURL()).isEqualTo(uri.toURL());
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertThat(basic.getClientID().getValue()).isEqualTo("123");
		assertThat(basic.getClientSecret().getValue()).isEqualTo("secret");
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
		assertThat(params.get("code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(Scope.parse(MultivaluedMapUtils.getFirstValue(params, "scope"))).isEqualTo(new Scope("openid", "email"));
		assertThat(params.get("resource")).isEqualTo(Arrays.asList("https://rs1.com", "https://rs2.com"));
		assertThat(MultivaluedMapUtils.getFirstValue(params, "x")).isEqualTo("100");
		assertThat(MultivaluedMapUtils.getFirstValue(params, "y")).isEqualTo("200");
		assertThat(params).hasSize(6);
	}

	@Test
	public void testConstructorWithClientAuthenticationAndNoScope()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID("123"), new Secret("secret"));
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);

		TokenRequest request = new TokenRequest(uri, clientAuth, grant);

		assertThat(request.getEndpointURI()).isEqualTo(uri);
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();
		assertThat(request.getResources()).isNull();
		assertThat(request.getExistingGrant()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getURL()).isEqualTo(uri.toURL());
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		ClientSecretBasic basic = ClientSecretBasic.parse(httpRequest.getAuthorization());
		assertThat(basic.getClientID().getValue()).isEqualTo("123");
		assertThat(basic.getClientSecret().getValue()).isEqualTo("secret");
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
		assertThat(params.get("code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(params).hasSize(2);
	}

	@Test
	public void testConstructorWithPubKeyTLSClientAuth()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new SelfSignedTLSClientAuthentication(new ClientID("123"), (SSLSocketFactory)null);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);

		TokenRequest request = new TokenRequest(uri, clientAuth, grant);

		assertThat(request.getEndpointURI()).isEqualTo(uri);
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();
		assertThat(request.getResources()).isNull();
		assertThat(request.getExistingGrant()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getURL()).isEqualTo(uri.toURL());
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
		assertThat(params.get("code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(params.get("client_id")).isEqualTo(Collections.singletonList("123"));
		assertThat(params).hasSize(3);
	}

	@Test
	public void testConstructorWithTLSClientAuth()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientAuthentication clientAuth = new PKITLSClientAuthentication(new ClientID("123"), (SSLSocketFactory) null);
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), null);

		TokenRequest request = new TokenRequest(uri, clientAuth, grant);

		assertThat(request.getEndpointURI()).isEqualTo(uri);
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();
		assertThat(request.getResources()).isNull();
		assertThat(request.getExistingGrant()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getURL()).isEqualTo(uri.toURL());
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
		assertThat(params.get("code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(params.get("client_id")).isEqualTo(Collections.singletonList("123"));
		assertThat(params).hasSize(3);
	}

	@Test
	public void testRejectNullClientAuthentication()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");

		try {
			new TokenRequest(uri, (ClientAuthentication)null, new ClientCredentialsGrant(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The client authentication must not be null");
		}
	}

	@Test
	public void testPublicClientConstructor_minimal()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));

		TokenRequest request = new TokenRequest(uri, clientID, grant, null, null, null, null);

		assertThat(request.getEndpointURI()).isEqualTo(uri);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();
		assertThat(request.getResources()).isNull();
		assertThat(request.getExistingGrant()).isNull();
		assertThat(request.getCustomParameters().isEmpty()).isTrue();

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getURL()).isEqualTo(uri.toURL());
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getAuthorization()).isNull();
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
		assertThat(params.get("code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(params.get("client_id")).isEqualTo(Collections.singletonList("123"));
		assertThat(params.get("redirect_uri")).isEqualTo(Collections.singletonList("http://example.com/in"));
		assertThat(params).hasSize(4);
		
		request = TokenRequest.parse(httpRequest);
		
		assertThat(request.getEndpointURI()).isEqualTo(uri);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();
		assertThat(request.getResources()).isNull();
		assertThat(request.getExistingGrant()).isNull();
		assertThat(request.getCustomParameters().isEmpty()).isTrue();
	}

	@Test
	public void testPublicClientConstructor_allSet()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));
		Scope scope = new Scope("read", "write");
		List<URI> resources = Collections.singletonList(URI.create("https://rs1.com"));
		RefreshToken existingGrant = new RefreshToken("shei6zoGhijohquu");
		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));

		TokenRequest request = new TokenRequest(uri, clientID, grant, scope, resources, existingGrant, customParams);

		assertThat(request.getEndpointURI()).isEqualTo(uri);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isEqualTo(scope);
		assertThat(request.getResources()).isEqualTo(resources);
		assertThat(request.getExistingGrant()).isEqualTo(existingGrant);
		assertThat(request.getCustomParameters()).isEqualTo(customParams);
		assertThat(request.getCustomParameter("x")).isEqualTo(Collections.singletonList("100"));
		assertThat(request.getCustomParameter("y")).isEqualTo(Collections.singletonList("200"));

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getURL()).isEqualTo(uri.toURL());
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getAuthorization()).isNull();
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
		assertThat(params.get("code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(params.get("client_id")).isEqualTo(Collections.singletonList("123"));
		assertThat(params.get("redirect_uri")).isEqualTo(Collections.singletonList("http://example.com/in"));
		assertThat(params.get("scope")).isEqualTo(Collections.singletonList(scope.toString()));
		assertThat(params.get("resource")).isEqualTo(Collections.singletonList("https://rs1.com"));
		assertThat(params.get("existing_grant")).isEqualTo(Collections.singletonList(existingGrant.getValue()));
		assertThat(params.get("x")).isEqualTo(Collections.singletonList("100"));
		assertThat(params.get("y")).isEqualTo(Collections.singletonList("200"));
		assertThat(params).hasSize(9);
		
		request = TokenRequest.parse(httpRequest);
		
		assertThat(request.getEndpointURI()).isEqualTo(uri);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isEqualTo(scope);
		assertThat(request.getResources()).isEqualTo(resources);
		assertThat(request.getExistingGrant()).isEqualTo(existingGrant);
		assertThat(request.getCustomParameters()).isEqualTo(customParams);
		assertThat(request.getCustomParameter("x")).isEqualTo(Collections.singletonList("100"));
		assertThat(request.getCustomParameter("y")).isEqualTo(Collections.singletonList("200"));
	}

	@Test
	public void testConstructorWithClientIDAndNoScope()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));

		TokenRequest request = new TokenRequest(uri, clientID, grant);

		assertThat(request.getEndpointURI()).isEqualTo(uri);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();
		assertThat(request.getResources()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getURL()).isEqualTo(uri.toURL());
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getAuthorization()).isNull();
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
		assertThat(params.get("code")).isEqualTo(Collections.singletonList("abc"));
		assertThat(params.get("client_id")).isEqualTo(Collections.singletonList("123"));
		assertThat(params.get("redirect_uri")).isEqualTo(Collections.singletonList("http://example.com/in"));
		assertThat(params).hasSize(4);
	}


	public void testConstructorMissingClientID()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		ClientID clientID = null;
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode("abc"), new URI("http://example.com/in"));

		try {
			new TokenRequest(uri, clientID, grant, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The \"authorization_code\" grant type requires a \"client_id\" parameter");
		}
	}

	@Test
	public void testMinimalConstructor()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));
		Scope scope = Scope.parse("openid email");

		TokenRequest tokenRequest = new TokenRequest(uri, grant, scope);

		assertThat(tokenRequest.getEndpointURI()).isEqualTo(uri);
		assertThat(tokenRequest.getClientAuthentication()).isNull();
		assertThat(tokenRequest.getClientID()).isNull();
		assertThat(tokenRequest.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(tokenRequest.getScope()).isEqualTo(scope);
		assertThat(tokenRequest.getResources()).isNull();

		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		assertThat(httpRequest.getURL()).isEqualTo(uri.toURL());
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getAuthorization()).isNull();
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.PASSWORD.getValue()));
		assertThat(params.get("username")).isEqualTo(Collections.singletonList("alice"));
		assertThat(params.get("password")).isEqualTo(Collections.singletonList("secret"));
		assertThat(Scope.parse(MultivaluedMapUtils.getFirstValue(params, "scope"))).isEqualTo(Scope.parse("openid email"));
		assertThat(params).hasSize(4);
	}

	@Test
	public void testMinimalConstructorWithNoScope()
		throws Exception {

		URI uri = new URI("https://c2id.com/token");
		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));

		TokenRequest tokenRequest = new TokenRequest(uri, grant);

		assertThat(tokenRequest.getEndpointURI()).isEqualTo(uri);
		assertThat(tokenRequest.getClientAuthentication()).isNull();
		assertThat(tokenRequest.getClientID()).isNull();
		assertThat(tokenRequest.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(tokenRequest.getScope()).isNull();
		assertThat(tokenRequest.getResources()).isNull();

		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		assertThat(httpRequest.getURL()).isEqualTo(uri.toURL());
		assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpRequest.getAuthorization()).isNull();
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.PASSWORD.getValue()));
		assertThat(params.get("username")).isEqualTo(Collections.singletonList("alice"));
		assertThat(params.get("password")).isEqualTo(Collections.singletonList("secret"));
		assertThat(params).hasSize(3);
	}

	@Test
	public void testMissingClientCredentialsAuthentication()
		throws Exception {

		try {
			new TokenRequest(new URI("https://c2id.com/token"), new ClientCredentialsGrant(), null);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The \"client_credentials\" grant type requires client authentication");
		}
	}

	@Test
	public void testCodeGrantWithBasicSecret()
		throws Exception {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		String postBody =
			"grant_type=authorization_code" +
			"&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb";
		
		httpRequest.setQuery(postBody);
		
		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertThat(tr.getEndpointURI()).isEqualTo(new URI("https://connect2id.com/token/"));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertThat(authBasic.getMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(authBasic.toHTTPAuthorizationHeader()).isEqualTo("Basic " + authBasicString);
		assertThat(authBasic.getClientID().getValue()).isEqualTo("s6BhdRkqt3");

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant)tr.getAuthorizationGrant();
		assertThat(codeGrant.getType()).isEqualTo(GrantType.AUTHORIZATION_CODE);
		assertThat(codeGrant.getAuthorizationCode().getValue()).isEqualTo("SplxlOBeZQQYbYS6WxSbIA");
		assertThat(codeGrant.getRedirectionURI().toString()).isEqualTo("https://client.example.com/cb");

		assertThat(tr.getClientID()).isNull();
		assertThat(tr.getScope()).isNull();
		assertThat(tr.getResources()).isNull();
		
		httpRequest = tr.toHTTPRequest();
		
		assertThat(httpRequest.getURL()).isEqualTo(new URL("https://connect2id.com/token/"));
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
		assertThat(httpRequest.getAuthorization()).isEqualTo("Basic " + authBasicString);
		assertThat(httpRequest.getQueryParameters().get("grant_type")).isEqualTo(Collections.singletonList("authorization_code"));
		assertThat(httpRequest.getQueryParameters().get("code")).isEqualTo(Collections.singletonList("SplxlOBeZQQYbYS6WxSbIA"));
		assertThat(httpRequest.getQueryParameters().get("redirect_uri")).isEqualTo(Collections.singletonList("https://client.example.com/cb"));
		assertThat(httpRequest.getQueryParameters()).hasSize(3);
	}

	@Test
	public void testCodeGrantWithPKCE()
		throws Exception {
		
		AuthorizationCode code = new AuthorizationCode();
		URI redirectURI = URI.create("app://oauth-callback");
		CodeVerifier pkceVerifier = new CodeVerifier();
		
		TokenRequest tokenRequest = new TokenRequest(
			URI.create("https://c2id.com/token"),
			new ClientID("123"),
			new AuthorizationCodeGrant(code, redirectURI, pkceVerifier));
		
		HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
		
		assertThat(httpRequest.getAuthorization()).isNull(); // no client auth here
		
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
		
		Map<String, List<String>> params = httpRequest.getQueryParameters();
		assertThat(params.get("grant_type")).isEqualTo(Collections.singletonList(GrantType.AUTHORIZATION_CODE.getValue()));
		assertThat(params.get("code")).isEqualTo(Collections.singletonList(code.getValue()));
		assertThat(params.get("redirect_uri")).isEqualTo(Collections.singletonList(redirectURI.toString()));
		assertThat(params.get("client_id")).isEqualTo(Collections.singletonList("123"));
		assertThat(params.get("code_verifier")).isEqualTo(Collections.singletonList(pkceVerifier.getValue()));
		assertThat(params).hasSize(5);
	}

	@Test
	public void testParseCodeGrantWithPKCE()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		String postBody =
			"grant_type=authorization_code" +
			"&code=SplxlOBeZQQYbYS6WxSbIA" +
			"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb" +
			"&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" +
			"&client_id=123";

		httpRequest.setQuery(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertThat(tr.getEndpointURI()).isEqualTo(new URI("https://connect2id.com/token/"));

		assertThat(tr.getClientAuthentication()).isNull();
		assertThat(tr.getClientID()).isEqualTo(new ClientID("123"));

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant)tr.getAuthorizationGrant();
		assertThat(codeGrant.getType()).isEqualTo(GrantType.AUTHORIZATION_CODE);
		assertThat(codeGrant.getAuthorizationCode().getValue()).isEqualTo("SplxlOBeZQQYbYS6WxSbIA");
		assertThat(codeGrant.getRedirectionURI().toString()).isEqualTo("https://client.example.com/cb");
		assertThat(codeGrant.getCodeVerifier().getValue()).isEqualTo("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");

		httpRequest = tr.toHTTPRequest();
		
		assertThat(httpRequest.getURL()).isEqualTo(new URL("https://connect2id.com/token/"));
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
		assertThat(httpRequest.getAuthorization()).isNull();
		assertThat(httpRequest.getQueryParameters().get("grant_type")).isEqualTo(Collections.singletonList("authorization_code"));
		assertThat(httpRequest.getQueryParameters().get("code")).isEqualTo(Collections.singletonList("SplxlOBeZQQYbYS6WxSbIA"));
		assertThat(httpRequest.getQueryParameters().get("redirect_uri")).isEqualTo(Collections.singletonList("https://client.example.com/cb"));
		assertThat(httpRequest.getQueryParameters().get("code_verifier")).isEqualTo(Collections.singletonList("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
		assertThat(httpRequest.getQueryParameters().get("client_id")).isEqualTo(Collections.singletonList("123"));
		assertThat(httpRequest.getQueryParameters()).hasSize(5);
	}

	@Test
	public void testParseRefreshTokenGrantWithBasicSecret()
		throws Exception {
	
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);
		
		final String postBody =
			"grant_type=refresh_token" +
			"&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA";
		
		httpRequest.setQuery(postBody);
		
		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertThat(tr.getEndpointURI()).isEqualTo(new URI("https://connect2id.com/token/"));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertThat(authBasic.getMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(authBasic.toHTTPAuthorizationHeader()).isEqualTo("Basic " + authBasicString);
		assertThat(authBasic.getClientID().getValue()).isEqualTo("s6BhdRkqt3");

		RefreshTokenGrant rtGrant = (RefreshTokenGrant)tr.getAuthorizationGrant();
		assertThat(rtGrant.getType()).isEqualTo(GrantType.REFRESH_TOKEN);
		assertThat(rtGrant.getRefreshToken().getValue()).isEqualTo("tGzv3JOkF0XG5Qx2TlKWIA");
		
		httpRequest = tr.toHTTPRequest();
		
		assertThat(httpRequest.getURL()).isEqualTo(new URL("https://connect2id.com/token/"));
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
		assertThat(httpRequest.getAuthorization()).isEqualTo("Basic " + authBasicString);
		assertThat(httpRequest.getQuery()).isEqualTo(postBody);
	}

	@Test
	public void testParsePasswordCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		final String postBody = "grant_type=password&username=johndoe&password=A3ddj3w";

		httpRequest.setQuery(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertThat(tr.getEndpointURI()).isEqualTo(new URI("https://connect2id.com/token/"));

		assertThat(tr.getClientAuthentication()).isNull();
		assertThat(tr.getClientID()).isNull();

		ResourceOwnerPasswordCredentialsGrant pwdGrant = (ResourceOwnerPasswordCredentialsGrant)tr.getAuthorizationGrant();
		assertThat(pwdGrant.getType()).isEqualTo(GrantType.PASSWORD);
		assertThat(pwdGrant.getUsername()).isEqualTo("johndoe");
		assertThat(pwdGrant.getPassword().getValue()).isEqualTo("A3ddj3w");

		assertThat(tr.getScope()).isNull();

		httpRequest = tr.toHTTPRequest();
		
		assertThat(httpRequest.getURL()).isEqualTo(new URL("https://connect2id.com/token/"));
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
		assertThat(httpRequest.getAuthorization()).isNull();
		assertThat(httpRequest.getQueryParameters().get("grant_type")).isEqualTo(Collections.singletonList("password"));
		assertThat(httpRequest.getQueryParameters().get("username")).isEqualTo(Collections.singletonList("johndoe"));
		assertThat(httpRequest.getQueryParameters().get("password")).isEqualTo(Collections.singletonList("A3ddj3w"));
		assertThat(httpRequest.getQueryParameters()).hasSize(3);
	}

	@Test
	public void testParsePasswordCredentialsGrantWithClientAuthentication()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=password&username=johndoe&password=A3ddj3w";

		httpRequest.setQuery(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertThat(tr.getEndpointURI()).isEqualTo(new URI("https://connect2id.com/token/"));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertThat(authBasic.getMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(authBasic.toHTTPAuthorizationHeader()).isEqualTo("Basic " + authBasicString);
		assertThat(authBasic.getClientID().getValue()).isEqualTo("s6BhdRkqt3");

		ResourceOwnerPasswordCredentialsGrant pwdGrant = (ResourceOwnerPasswordCredentialsGrant)tr.getAuthorizationGrant();
		assertThat(pwdGrant.getType()).isEqualTo(GrantType.PASSWORD);
		assertThat(pwdGrant.getUsername()).isEqualTo("johndoe");
		assertThat(pwdGrant.getPassword().getValue()).isEqualTo("A3ddj3w");

		assertThat(tr.getScope()).isNull();

		httpRequest = tr.toHTTPRequest();
		
		assertThat(httpRequest.getURL()).isEqualTo(new URL("https://connect2id.com/token/"));
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
		assertThat(httpRequest.getAuthorization()).isEqualTo("Basic " + authBasicString);
		assertThat(httpRequest.getQueryParameters().get("grant_type")).isEqualTo(Collections.singletonList("password"));
		assertThat(httpRequest.getQueryParameters().get("username")).isEqualTo(Collections.singletonList("johndoe"));
		assertThat(httpRequest.getQueryParameters().get("password")).isEqualTo(Collections.singletonList("A3ddj3w"));
		assertThat(httpRequest.getQueryParameters()).hasSize(3);
	}

	@Test
	public void testParseClientCredentialsGrant()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		final String authBasicString = "czZCaGRSa3F0MzpnWDFmQmF0M2JW";
		httpRequest.setAuthorization("Basic " + authBasicString);

		final String postBody = "grant_type=client_credentials";

		httpRequest.setQuery(postBody);

		TokenRequest tr = TokenRequest.parse(httpRequest);
		
		assertThat(tr.getEndpointURI()).isEqualTo(new URI("https://connect2id.com/token/"));

		ClientSecretBasic authBasic = (ClientSecretBasic)tr.getClientAuthentication();
		assertThat(authBasic.getMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(authBasic.toHTTPAuthorizationHeader()).isEqualTo("Basic " + authBasicString);
		assertThat(authBasic.getClientID().getValue()).isEqualTo("s6BhdRkqt3");

		ClientCredentialsGrant clientCredentialsGrant = (ClientCredentialsGrant)tr.getAuthorizationGrant();
		assertThat(clientCredentialsGrant.getType()).isEqualTo(GrantType.CLIENT_CREDENTIALS);

		assertThat(tr.getScope()).isNull();

		httpRequest = tr.toHTTPRequest();
		
		assertThat(httpRequest.getURL()).isEqualTo(new URL("https://connect2id.com/token/"));
		assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
		assertThat(httpRequest.getAuthorization()).isEqualTo("Basic " + authBasicString);
		assertThat(httpRequest.getQuery()).isEqualTo(postBody);
	}

	@Test
	public void testParseClientCredentialsGrantMissingAuthentication()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		final String postBody = "grant_type=client_credentials";

		httpRequest.setQuery(postBody);

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_CLIENT);
		}
	}

	@Test
	public void testSupportTokenRequestClientSecretPostSerialization()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode();
		URI endpointUri = new URI("https://token.endpoint.uri/token");
		URI redirectUri = new URI("https://arbitrary.redirect.uri/");
		ClientID clientId = new ClientID("client");
		Secret secret = new Secret("secret");
		ClientSecretPost clientAuthentication = new ClientSecretPost(clientId,secret);
		AuthorizationGrant grant = new AuthorizationCodeGrant(code,redirectUri);
		TokenRequest request = new TokenRequest(endpointUri,clientAuthentication,grant);

		HTTPRequest httpRequest = request.toHTTPRequest();
		TokenRequest reconstructedRequest = TokenRequest.parse(httpRequest);
		
		assertThat(reconstructedRequest.getClientAuthentication().getClientID().getValue()).isEqualTo("client");
		assertThat(((ClientSecretPost) reconstructedRequest.getClientAuthentication()).getClientSecret().getValue()).isEqualTo("secret");
		assertThat(((AuthorizationCodeGrant) reconstructedRequest.getAuthorizationGrant()).getAuthorizationCode()).isEqualTo(code);
	}


	// See issue 141
	@Test
	public void testEmptyClientSecret()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://googleapis.com/oauth2/v3/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery("code=0a2b49a9-985d-47cb-b36f-be9ed4927b4c&redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground&client_id=google&client_secret=&scope=&grant_type=authorization_code");

		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);

		assertThat(tokenRequest.getEndpointURI().toString()).isEqualTo("https://googleapis.com/oauth2/v3/token");
		assertThat(tokenRequest.getClientAuthentication()).isNull();
		AuthorizationGrant grant = tokenRequest.getAuthorizationGrant();
		assertThat(grant).isInstanceOf(AuthorizationCodeGrant.class);

		AuthorizationCodeGrant codeGrant = (AuthorizationCodeGrant)grant;
		assertThat(codeGrant.getAuthorizationCode().getValue()).isEqualTo("0a2b49a9-985d-47cb-b36f-be9ed4927b4c");
		assertThat(codeGrant.getRedirectionURI().toString()).isEqualTo("https://developers.google.com/oauthplayground");

		assertThat(tokenRequest.getClientID().getValue()).isEqualTo("google");

		assertThat(tokenRequest.getScope().isEmpty()).isTrue();
	}

	@Test
	public void testCodeGrant_confidentialClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("secret");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("xyz"), new URI("https://example.com/cb"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, codeGrant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getAuthorizationGrant()).isEqualTo(codeGrant);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication().getClientID()).isEqualTo(clientID);
		assertThat(((ClientSecretBasic)request.getClientAuthentication()).getClientSecret()).isEqualTo(clientSecret);
		assertThat(request.getAuthorizationGrant()).isEqualTo(codeGrant);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testCodeGrant_publicClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("xyz"), new URI("https://example.com/cb"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, codeGrant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(codeGrant);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(codeGrant);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testCodeGrant_publicClient_pkce()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("xyz"), new URI("https://example.com/cb"), new CodeVerifier());

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, codeGrant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(codeGrant);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(codeGrant);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testCodeGrant_rejectUnregisteredClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		AuthorizationCodeGrant codeGrant = new AuthorizationCodeGrant(new AuthorizationCode("xyz"), new URI("https://example.com/cb"));

		try {
			new TokenRequest(tokenEndpoint, codeGrant);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The \"authorization_code\" grant type requires a \"client_id\" parameter");
		}


		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery(URLUtils.serializeParameters(codeGrant.toParameters()));

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing required \"client_id\" parameter");
		}
	}

	@Test
	public void testPasswordGrant_confidentialClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("secret");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		ResourceOwnerPasswordCredentialsGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, passwordGrant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getAuthorizationGrant()).isEqualTo(passwordGrant);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication().getClientID()).isEqualTo(clientAuth.getClientID());
		assertThat(request.getAuthorizationGrant()).isEqualTo(passwordGrant);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testPasswordGrant_publicClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		ResourceOwnerPasswordCredentialsGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, passwordGrant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(passwordGrant);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(passwordGrant);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testPasswordGrant_unspecifiedClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ResourceOwnerPasswordCredentialsGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret("secret"));

		TokenRequest request = new TokenRequest(tokenEndpoint, passwordGrant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(passwordGrant);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(passwordGrant);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testRefreshTokenGrant_confidentialClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("secret");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken("xyz"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, grant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication().getClientID()).isEqualTo(clientAuth.getClientID());
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testRefreshTokenGrant_publicClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken("xyz"));

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, grant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testRefreshTokenGrant_unspecifiedClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		RefreshTokenGrant grant = new RefreshTokenGrant(new RefreshToken("xyz"));

		TokenRequest request = new TokenRequest(tokenEndpoint, grant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant()).isEqualTo(grant);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testClientCredentialsGrant_confidentialClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("secret");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
		ClientCredentialsGrant grant = new ClientCredentialsGrant();

		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, grant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getAuthorizationGrant().getType()).isEqualTo(GrantType.CLIENT_CREDENTIALS);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication().getClientID()).isEqualTo(clientAuth.getClientID());
		assertThat(request.getAuthorizationGrant().getType()).isEqualTo(GrantType.CLIENT_CREDENTIALS);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testClientCredentialsGrant_rejectPublicClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		ClientCredentialsGrant grant = new ClientCredentialsGrant();

		try {
			new TokenRequest(tokenEndpoint, clientID, grant);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The \"client_credentials\" grant type requires client authentication");
		}

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery(URLUtils.serializeParameters(grant.toParameters()));

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing client authentication");
		}
	}

	@Test
	public void testClientCredentialsGrant_rejectUnregisteredClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientCredentialsGrant grant = new ClientCredentialsGrant();

		try {
			new TokenRequest(tokenEndpoint, grant);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The \"client_credentials\" grant type requires client authentication");
		}

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setQuery(URLUtils.serializeParameters(grant.toParameters()));

		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing client authentication");
		}
	}

	@Test
	public void testJWTBearerGrant_confidentialClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret("secret");
		ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

		SignedJWT jwt = JWTAssertionFactory.create(new JWTAssertionDetails(
			new Issuer("123"),
			new Subject("123"),
			new Audience(tokenEndpoint)),
			JWSAlgorithm.HS256,
			new Secret());
		JWTBearerGrant grant = new JWTBearerGrant(jwt);

		TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, grant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication()).isEqualTo(clientAuth);
		assertThat(request.getAuthorizationGrant().getType()).isEqualTo(GrantType.JWT_BEARER);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication().getClientID()).isEqualTo(clientAuth.getClientID());
		assertThat(request.getAuthorizationGrant().getType()).isEqualTo(GrantType.JWT_BEARER);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testJWTBearerGrant_publicClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		ClientID clientID = new ClientID("123");

		SignedJWT jwt = JWTAssertionFactory.create(new JWTAssertionDetails(
				new Issuer("123"),
				new Subject("123"),
				new Audience(tokenEndpoint)),
			JWSAlgorithm.HS256,
			new Secret());
		JWTBearerGrant grant = new JWTBearerGrant(jwt);

		TokenRequest request = new TokenRequest(tokenEndpoint, clientID, grant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant().getType()).isEqualTo(GrantType.JWT_BEARER);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isEqualTo(clientID);
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant().getType()).isEqualTo(GrantType.JWT_BEARER);
		assertThat(request.getScope()).isNull();
	}

	@Test
	public void testJWTBearerGrant_unregisteredClient()
		throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/token");
		SignedJWT jwt = JWTAssertionFactory.create(new JWTAssertionDetails(
				new Issuer("123"),
				new Subject("123"),
				new Audience(tokenEndpoint)),
			JWSAlgorithm.HS256,
			new Secret());
		JWTBearerGrant grant = new JWTBearerGrant(jwt);

		TokenRequest request = new TokenRequest(tokenEndpoint, grant);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant().getType()).isEqualTo(GrantType.JWT_BEARER);
		assertThat(request.getScope()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = TokenRequest.parse(httpRequest);

		assertThat(request.getEndpointURI()).isEqualTo(tokenEndpoint);
		assertThat(request.getClientID()).isNull();
		assertThat(request.getClientAuthentication()).isNull();
		assertThat(request.getAuthorizationGrant().getType()).isEqualTo(GrantType.JWT_BEARER);
		assertThat(request.getScope()).isNull();
	}




	// https://bitbucket.org/connect2id/openid-connect-dev-client/issues/5/stripping-equal-sign-from-access_code-in
	@Test
	public void testCodeGrantEqualsCharEncoding()
		throws Exception {

		AuthorizationCode code = new AuthorizationCode("abc=");
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(code, URI.create("https://example.com/cb"));

		TokenRequest request = new TokenRequest(URI.create("https://openid.c2id.com/token"), new ClientID("123"), grant);

		HTTPRequest httpRequest = request.toHTTPRequest();

		String query = httpRequest.getQuery();
		List<String> queryTokens = Arrays.asList(query.split("&"));

		assertThat(queryTokens).contains("client_id=123");
		assertThat(queryTokens).contains("grant_type=authorization_code");
		assertThat(queryTokens).contains("code=abc%3D");
		assertThat(queryTokens).contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcb");
		assertThat(queryTokens).hasSize(4);
	}

	@Test
	public void testCustomParams_codeGrant_basicAuth()
		throws Exception {

		AuthorizationGrant grant = new AuthorizationCodeGrant(new AuthorizationCode(), URI.create("https://example.com/cb"));
		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretBasic(new ClientID(), new Secret()), grant, Scope.parse("read write"), null, customParams);

		assertThat(request.getCustomParameters()).isEqualTo(customParams);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertThat(httpRequest.getQueryParameters().get("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));
		assertThat(httpRequest.getQueryParameters()).hasSize(5);

		request = TokenRequest.parse(httpRequest);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));
		assertThat(request.getCustomParameters()).hasSize(1);
	}

	@Test
	public void testCustomParams_codeGrant_postAuth()
		throws Exception {

		AuthorizationGrant grant = new AuthorizationCodeGrant(new AuthorizationCode(), URI.create("https://example.com/cb"));
		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretPost(new ClientID(), new Secret()), grant, Scope.parse("read write"), null, customParams);

		assertThat(request.getCustomParameters()).isEqualTo(customParams);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertThat(httpRequest.getQueryParameters().get("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));
		assertThat(httpRequest.getQueryParameters()).hasSize(7);

		request = TokenRequest.parse(httpRequest);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));
		assertThat(request.getCustomParameters()).hasSize(1);
	}

	@Test
	public void testCustomParams_passwordGrant_postAuth()
		throws Exception {

		AuthorizationGrant grant = new ResourceOwnerPasswordCredentialsGrant("alice", new Secret());
		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretPost(new ClientID(), new Secret()), grant, Scope.parse("read write"), null, customParams);

		assertThat(request.getCustomParameters()).isEqualTo(customParams);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));

		HTTPRequest httpRequest = request.toHTTPRequest();
		assertThat(httpRequest.getQueryParameters().get("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));
		assertThat(httpRequest.getQueryParameters()).hasSize(7);

		request = TokenRequest.parse(httpRequest);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));
		assertThat(request.getCustomParameters()).hasSize(1);
	}

	@Test
	public void testCustomParams_clientCredentialsGrant_basicAuth()
		throws Exception {

		AuthorizationGrant grant = new ClientCredentialsGrant();
		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretBasic(new ClientID(), new Secret()), grant, Scope.parse("read write"), null, customParams);

		assertThat(request.getCustomParameters()).isEqualTo(customParams);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		System.out.println(httpRequest.getQuery());
		assertThat(httpRequest.getQueryParameters().get("grant_type")).isEqualTo(Collections.singletonList("client_credentials"));
		assertThat(httpRequest.getQueryParameters().get("scope")).isEqualTo(Collections.singletonList("read write"));
		assertThat(httpRequest.getQueryParameters().get("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));
		assertThat(httpRequest.getQueryParameters()).hasSize(3);

		request = TokenRequest.parse(httpRequest);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));
		assertThat(request.getCustomParameters()).hasSize(1);
	}

	@Test
	public void testCustomParams_clientCredentialsGrant_postAuth()
		throws Exception {

		AuthorizationGrant grant = new ClientCredentialsGrant();
		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretPost(new ClientID(), new Secret()), grant, Scope.parse("read write"), null, customParams);

		assertThat(request.getCustomParameters()).isEqualTo(customParams);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		System.out.println(httpRequest.getQuery());
		assertThat(httpRequest.getQueryParameters().get("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));

		request = TokenRequest.parse(httpRequest);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));
		assertThat(request.getCustomParameters()).hasSize(1);
	}

	@Test
	public void testCustomParams_clientCredentialsGrant_jwtAuth()
		throws Exception {

		AuthorizationGrant grant = new ClientCredentialsGrant();
		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("data", Collections.singletonList("http://xxxxxx/PartyOData"));

		TokenRequest request = new TokenRequest(URI.create("https://c2id.com/token"), new ClientSecretJWT(new ClientID(), URI.create("https://c2id.com/token"), JWSAlgorithm.HS256, new Secret()), grant, Scope.parse("read write"), null, customParams);

		assertThat(request.getCustomParameters()).isEqualTo(customParams);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));

		HTTPRequest httpRequest = request.toHTTPRequest();

		System.out.println(httpRequest.getQuery());
		assertThat(httpRequest.getQueryParameters().get("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));

		request = TokenRequest.parse(httpRequest);
		assertThat(request.getCustomParameter("data")).isEqualTo(Collections.singletonList("http://xxxxxx/PartyOData"));
		System.out.println(request.getCustomParameters());
		assertThat(request.getCustomParameters()).hasSize(1);
	}

	@Test
	public void testCodeGrantWithBasicSecret_parseMalformedBasicAuth_missingDelimiter()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://connect2id.com/token/"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		
		httpRequest.setAuthorization("Basic " + Base64Value.encode("alice"));
		
		String postBody =
			"grant_type=authorization_code" +
				"&code=SplxlOBeZQQYbYS6WxSbIA" +
				"&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb";
		
		httpRequest.setQuery(postBody);
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Malformed client secret basic authentication (see RFC 6749, section 2.3.1): Missing credentials delimiter \":\"");
			
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.toString());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Malformed client secret basic authentication (see RFC 6749, section 2.3.1): Missing credentials delimiter \":\"");
		}
	}

	@Test
	// Reject basic + client_secret_jwt auth present in the same token request
	public void testRejectMultipleClientAuthMethods()
		throws Exception {
		
		ClientID clientID = new ClientID("123");
		Secret clientSecret = new Secret();
		
		URL tokenEndpoint = new URL("https://c2id.com/token");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, tokenEndpoint);
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setAuthorization(new ClientSecretBasic(clientID, clientSecret).toHTTPAuthorizationHeader());
		
		AuthorizationCodeGrant grant = new AuthorizationCodeGrant(new AuthorizationCode(), URI.create("https://example.com/cb"));
		
		ClientSecretJWT clientSecretJWT = new ClientSecretJWT(clientID, tokenEndpoint.toURI(), JWSAlgorithm.HS256, clientSecret);
		
		Map<String, List<String>> bodyParams = new HashMap<>();
		bodyParams.putAll(grant.toParameters());
		bodyParams.putAll(clientSecretJWT.toParameters());
		
		httpRequest.setQuery(URLUtils.serializeParameters(bodyParams));
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Multiple conflicting client authentication methods found: Basic and JWT assertion");
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Multiple conflicting client authentication methods found: Basic and JWT assertion");
		}
	}
	
	
	// iss208
	@Test
	public void testClientSecretBasicDecodingException()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://c2id.com/token"));
		httpRequest.setAuthorization("Basic KVQdqB25zeFg4duoJf7ZYo4wDMXtQjqlpxWdgFm06vc");
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
		httpRequest.setHeader("Cache-Control", "no-cache");
		httpRequest.setQuery("grant_type=authorization_code" +
			"&code=a0x3DwU3vE9Ad1CbWdy1LQ.KaPahOgJJjODKWE47-DXzg" +
			"&redirect_uri=dufryred%3A%2F%2Foauth.callback" +
			"&code_verifier=VjdnvRw3_nTdhoWLcwYBjVt2wQnklP-gcXRmFXvQcM6OhMqDQOXWhXQvqHeCbgOlJHsu8xDVyRU0vRaMzuEKbQ" +
			"&client_id=47ub27skbkcf2");
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Malformed client secret basic authentication (see RFC 6749, section 2.3.1): Invalid URL encoding");
		}
	}

	@Test
	public void testParseResourceIndicatorsExample()
		throws Exception {
		
		// POST /as/token.oauth2 HTTP/1.1
		// Host: authorization-server.example.com
		// Authorization: Basic czZCaGRSa3F0Mzpoc3FFelFsVW9IQUU5cHg0RlNyNHlJ
		// Content-Type: application/x-www-form-urlencoded
		//
		// grant_type=refresh_token
		// &refresh_token=4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH
		// &resource=https%3A%2F%2Frs.example.com%2F
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://authorization-server.example.com/as/token.oauth2"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0Mzpoc3FFelFsVW9IQUU5cHg0RlNyNHlJ");
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setQuery("grant_type=refresh_token&refresh_token=4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH&resource=https%3A%2F%2Frs.example.com%2F");
		
		TokenRequest tokenRequest = TokenRequest.parse(httpRequest);
		
		assertThat(tokenRequest.getEndpointURI()).isEqualTo(httpRequest.getURL().toURI());
		assertThat(tokenRequest.getClientAuthentication()).isInstanceOf(ClientSecretBasic.class);
		ClientSecretBasic clientSecretBasic = (ClientSecretBasic) tokenRequest.getClientAuthentication();
		assertThat(clientSecretBasic.getClientID().getValue()).isEqualTo("s6BhdRkqt3");
		assertThat(clientSecretBasic.getClientSecret().getValue()).isEqualTo("hsqEzQlUoHAE9px4FSr4yI");
		
		assertThat(((RefreshTokenGrant) tokenRequest.getAuthorizationGrant()).getRefreshToken()).isEqualTo(new RefreshToken("4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH"));
		assertThat(tokenRequest.getResources()).isEqualTo(Collections.singletonList(URI.create("https://rs.example.com/")));
	}

	@Test
	public void testParseResource_rejectNonAbsoluteURI()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://authorization-server.example.com/as/token.oauth2"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0Mzpoc3FFelFsVW9IQUU5cHg0RlNyNHlJ");
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setQuery("grant_type=refresh_token&refresh_token=4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH&resource=https%3A%2F%2F%2F");
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_RESOURCE);
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid \"resource\" parameter: Must be an absolute URI and with no query or fragment: https:///");
		}
	}

	@Test
	public void testParseResource_rejectURIWithQuery()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://authorization-server.example.com/as/token.oauth2"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0Mzpoc3FFelFsVW9IQUU5cHg0RlNyNHlJ");
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setQuery("grant_type=refresh_token&refresh_token=4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH&resource=https%3A%2F%2Frs.example.com%2F?query");
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_RESOURCE);
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid \"resource\" parameter: Must be an absolute URI and with no query or fragment: https://rs.example.com/?query");
		}
	}

	@Test
	public void testParseResource_rejectURIWithFragment()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://authorization-server.example.com/as/token.oauth2"));
		httpRequest.setAuthorization("Basic czZCaGRSa3F0Mzpoc3FFelFsVW9IQUU5cHg0RlNyNHlJ");
		httpRequest.setContentType("application/x-www-form-urlencoded");
		httpRequest.setQuery("grant_type=refresh_token&refresh_token=4LTC8lb0acc6Oy4esc1Nk9BWC0imAwH&resource=https%3A%2F%2Frs.example.com%2F#fragment");
		
		try {
			TokenRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_RESOURCE);
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid \"resource\" parameter: Must be an absolute URI and with no query or fragment: https://rs.example.com/#fragment");
		}
	}
}
