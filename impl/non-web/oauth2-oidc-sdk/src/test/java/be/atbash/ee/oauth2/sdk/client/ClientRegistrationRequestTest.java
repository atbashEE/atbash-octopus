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
package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.oauth2.sdk.GrantType;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACVerifier;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.Test;

import javax.json.JsonObject;
import java.net.URI;
import java.net.URL;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the client registration request class.
 */
public class ClientRegistrationRequestTest  {


	@SuppressWarnings("unchecked")
	@Test
	public void testSerializeAndParse()
		throws Exception {

		URI uri = new URI("https://c2id.com/client-reg");

		ClientMetadata metadata = new ClientMetadata();
		metadata.setName("My test app");
		metadata.setRedirectionURI(new URI("https://client.com/callback"));
		metadata.applyDefaults();

		BearerAccessToken accessToken = new BearerAccessToken();

		ClientRegistrationRequest request = new ClientRegistrationRequest(uri, metadata, accessToken);

		HTTPRequest httpRequest = request.toHTTPRequest();

		assertThat(httpRequest.getURL().toString()).isEqualTo(uri.toString());
		assertThat(httpRequest.getContentType().toString().startsWith("application/json")).isTrue();

		JsonObject jsonObject = httpRequest.getQueryAsJSONObject();

		List<String> stringList = JSONObjectUtils.getStringList(jsonObject, "redirect_uris");
		assertThat(stringList.get(0)).isEqualTo(metadata.getRedirectionURIs().iterator().next().toString());
		assertThat(jsonObject.getString("client_name")).isEqualTo(metadata.getName());
		assertThat(jsonObject.getString("token_endpoint_auth_method")).isEqualTo("client_secret_basic");
		stringList = JSONObjectUtils.getStringList(jsonObject, "response_types");
		assertThat(stringList.get(0)).isEqualTo("code");
		stringList = JSONObjectUtils.getStringList(jsonObject, "grant_types");
		assertThat(stringList.get(0)).isEqualTo("authorization_code");

		request = ClientRegistrationRequest.parse(httpRequest);

		assertThat(request.getClientMetadata().getName()).isEqualTo(metadata.getName());
		assertThat(request.getClientMetadata().getRedirectionURIs().iterator().next().toString()).isEqualTo(metadata.getRedirectionURIs().iterator().next().toString());
		assertThat(request.getClientMetadata().getTokenEndpointAuthMethod()).isEqualTo(metadata.getTokenEndpointAuthMethod());
		assertThat(request.getClientMetadata().getResponseTypes().iterator().next().toString()).isEqualTo("code");
		assertThat(request.getClientMetadata().getGrantTypes().iterator().next().toString()).isEqualTo("authorization_code");
	}

	@Test
	public void _testExampleRegisterForCodeGrant()
		throws Exception {
		
		// The client registration endpoint
		URI clientsEndpoint = new URI("https://demo.c2id.com/c2id/clients");
		
		// Master API token for the clients endpoint
		BearerAccessToken masterToken = new BearerAccessToken("ztucZS1ZyFKgh0tUEruUtiSTXhnexmd6");
		
		// We want to register a client for the code grant
		ClientMetadata clientMetadata = new ClientMetadata();
		clientMetadata.setGrantTypes(Collections.singleton(GrantType.AUTHORIZATION_CODE));
		clientMetadata.setRedirectionURI(URI.create("https://example.com/cb"));
		clientMetadata.setName("My Client App");
		
		ClientRegistrationRequest regRequest = new ClientRegistrationRequest(
			clientsEndpoint,
			clientMetadata,
			masterToken
		);
		
		HTTPResponse httpResponse = regRequest.toHTTPRequest().send();
		
		ClientRegistrationResponse regResponse = ClientRegistrationResponse.parse(httpResponse);
		
		if (! regResponse.indicatesSuccess()) {
			// We have an error
			ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse)regResponse;
			System.err.println(errorResponse.getErrorObject());
			return;
		}
		
		// Successful registration
		ClientInformationResponse successResponse = (ClientInformationResponse)regResponse;
		
		ClientInformation clientInfo = successResponse.getClientInformation();
		
		// The client credentials - store them:
		// FIXME Create a proper test
		// The client_id
		//System.out.println("Client ID: " + clientInfo.getID());
		
		// The client_secret
		//System.out.println("Client secret: " + clientInfo.getSecret().getValue());
		
		// The client's registration resource
		//System.out.println("Client registration URI: " + clientInfo.getRegistrationURI());
		
		// The token for accessing the client's registration (for update, etc)
		//System.out.println("Client reg access token: " + clientInfo.getRegistrationAccessToken());
		
		// Print the remaining client metadata

		// Query
		ClientReadRequest readRequest = new ClientReadRequest(
			clientInfo.getRegistrationURI(),
			clientInfo.getRegistrationAccessToken()
		);
		
		httpResponse = readRequest.toHTTPRequest().send();
		
		regResponse = ClientRegistrationResponse.parse(httpResponse);
		
		if (! regResponse.indicatesSuccess()) {
			// We have an error
			ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse)regResponse;
			System.err.println(errorResponse.getErrorObject());
			return;
		}
		
		// Success
		successResponse = (ClientInformationResponse)regResponse;
		

		// Update client name
		clientMetadata = clientInfo.getMetadata();
		clientMetadata.setName("My app has a new name");
		
		// Send request
		ClientUpdateRequest updateRequest = new ClientUpdateRequest(
			clientInfo.getRegistrationURI(),
			clientInfo.getID(),
			clientInfo.getRegistrationAccessToken(),
			clientMetadata,
			clientInfo.getSecret()
		);
	
		httpResponse = updateRequest.toHTTPRequest().send();
		
		regResponse = ClientRegistrationResponse.parse(httpResponse);
		
		if (! regResponse.indicatesSuccess()) {
			// We have an error
			ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse)regResponse;
			System.err.println(errorResponse.getErrorObject());
			return;
		}
		
		// Success
		successResponse = (ClientInformationResponse)regResponse;
		
		// Ensure the client name has been updated
		clientInfo = successResponse.getClientInformation();

		
		// Request deletion
		ClientDeleteRequest deleteRequest = new ClientDeleteRequest(
			clientInfo.getRegistrationURI(),
			clientInfo.getRegistrationAccessToken()
		);
		
		httpResponse = deleteRequest.toHTTPRequest().send();
		
		regResponse = ClientRegistrationResponse.parse(httpResponse);
		
		if (! regResponse.indicatesSuccess()) {
			// We have an error
			ClientRegistrationErrorResponse errorResponse = (ClientRegistrationErrorResponse)regResponse;
			System.err.println(errorResponse.getErrorObject());
			return;
		}
		
		// Success: nothing returned
	}

	@Test
	public void testParse()
		throws Exception {
		
		URI endpointURI = new URI("https://server.example.com/register/");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpointURI.toURL());
		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);
		
		String json = "{"
			+ "    \"redirect_uris\":[\"https://client.example.org/callback\","
			+ "       \"https://client.example.org/callback2\"],"
			+ "    \"client_name\":\"My Example Client\","
			+ "    \"token_endpoint_auth_method\":\"client_secret_basic\","
			+ "    \"scope\":\"read write dolphin\","
			+ "    \"logo_uri\":\"https://client.example.org/logo.png\","
			+ "    \"jwks_uri\":\"https://client.example.org/my_public_keys.jwks\""
			+ "   }";
		
		
		httpRequest.setQuery(json);
		
		ClientRegistrationRequest request = ClientRegistrationRequest.parse(httpRequest);
		
		assertThat(request.getAccessToken()).isNull();
		
		ClientMetadata metadata = request.getClientMetadata();
		
		Set<URI> redirectURIs = metadata.getRedirectionURIs();
		assertThat(redirectURIs).contains(new URI("https://client.example.org/callback"));
		assertThat(redirectURIs).contains(new URI("https://client.example.org/callback2"));
		assertThat(redirectURIs).hasSize(2);
		
		assertThat(metadata.getName()).isEqualTo("My Example Client");

        assertThat(metadata.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		
		assertThat(metadata.getScope()).isEqualTo(Scope.parse("read write dolphin"));
		
		assertThat(metadata.getLogoURI()).isEqualTo(new URI("https://client.example.org/logo.png"));
		
		assertThat(metadata.getJWKSetURI()).isEqualTo(new URI("https://client.example.org/my_public_keys.jwks"));
	}

	@Test
	public void testSoftwareStatement()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://c2id.com")
			.build();

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
		jwt.sign(new MACSigner("01234567890123456789012345678901"));

		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		ClientRegistrationRequest request = new ClientRegistrationRequest(new URI("https://c2id.com/reg"), metadata, jwt, null);

		assertThat(request.getClientMetadata()).isEqualTo(metadata);
		assertThat(request.getSoftwareStatement()).isEqualTo(jwt);
		assertThat(request.getAccessToken()).isNull();

		HTTPRequest httpRequest = request.toHTTPRequest();

		request = ClientRegistrationRequest.parse(httpRequest);

		assertThat(request.getClientMetadata().getRedirectionURIs().iterator().next().toString()).isEqualTo("https://client.com/in");
		assertThat(request.getClientMetadata().getName()).isEqualTo("Test App");
		assertThat(request.getSoftwareStatement().getParsedString()).isEqualTo(jwt.serialize());
		assertThat(request.getSoftwareStatement().verify(new MACVerifier("01234567890123456789012345678901"))).isTrue();
	}

	@Test
	public void testRejectUnsignedSoftwareStatement()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
			.issuer("https://c2id.com")
			.build();

		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		try {
			new ClientRegistrationRequest(
				new URI("https://c2id.com/reg"),
				metadata,
				new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet),
				null);

		} catch (IllegalArgumentException e) {

			// ok
			assertThat(e.getMessage()).isEqualTo("The software statement JWT must be signed");
		}

	}

	@Test
	public void testRejectSoftwareStatementWithoutIssuer()
		throws Exception {

		SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build());
		jwt.sign(new MACSigner("01234567890123456789012345678901"));

		ClientMetadata metadata = new ClientMetadata();
		metadata.setRedirectionURI(new URI("https://client.com/in"));
		metadata.setName("Test App");

		try {
			new ClientRegistrationRequest(
				new URI("https://c2id.com/reg"),
				metadata,
				jwt,
				null);

		} catch (IllegalArgumentException e) {

			// ok
			assertThat(e.getMessage()).isEqualTo("The software statement JWT must contain an 'iss' claim");
		}
	}
	
	
	//     POST /register HTTP/1.1
	//     Content-Type: application/json
	//     Accept: application/json
	//     Host: server.example.com
	//     Authorization: Bearer
	//
	//     {
	//      "redirect_uris": [
	//        "https://client.example.org/callback",
	//        "https://client.example.org/callback2"],
	//      "client_name": "My Example Client",
	//      "token_endpoint_auth_method": "client_secret_basic",
	//     }
	@Test
	public void testParseExampleFromHTTPRequest()
		throws Exception {
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://server.example.com/register"));
		httpRequest.setAuthorization("Bearer ooyeph4wij2eyuagax4een8Eeshohpha");
		httpRequest.setContentType("application/json");
		httpRequest.setAccept("application/json");
		httpRequest.setQuery("{\n" +
			" \"redirect_uris\": [\n" +
			"   \"https://client.example.org/callback\",\n" +
			"   \"https://client.example.org/callback2\"],\n" +
			" \"client_name\": \"My Example Client\",\n" +
			" \"token_endpoint_auth_method\": \"client_secret_basic\"\n" +
			"}");
		
		ClientRegistrationRequest registrationRequest = ClientRegistrationRequest.parse(httpRequest);
		assertThat(registrationRequest.getAccessToken()).isEqualTo(new BearerAccessToken("ooyeph4wij2eyuagax4een8Eeshohpha"));
		assertThat(registrationRequest.getEndpointURI()).isEqualTo(new URI("https://server.example.com/register"));
		
		assertThat(registrationRequest.getClientMetadata().getRedirectionURIs()).isEqualTo(new HashSet<>(Arrays.asList(new URI("https://client.example.org/callback"), new URI("https://client.example.org/callback2"))));
		assertThat(registrationRequest.getClientMetadata().getName()).isEqualTo("My Example Client");
		assertThat(registrationRequest.getClientMetadata().getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
	}
}