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

package be.atbash.ee.oauth2.sdk.device;

import be.atbash.ee.oauth2.sdk.OAuth2Error;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.auth.ClientSecretBasic;
import be.atbash.ee.oauth2.sdk.auth.ClientSecretPost;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import org.junit.Test;

import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

public class DeviceAuthorizationRequestTest  {

	@Test
	public void testRegisteredParameters() {

		assertThat(DeviceAuthorizationRequest.getRegisteredParameterNames()).contains("client_id");
		assertThat(DeviceAuthorizationRequest.getRegisteredParameterNames()).contains("scope");
		assertThat(DeviceAuthorizationRequest.getRegisteredParameterNames()).hasSize(2);
	}

	@Test
	public void testMinimal() throws Exception {

		URI uri = new URI("https://c2id.com/devauthz/");

		ClientID clientID = new ClientID("123456");

		DeviceAuthorizationRequest req = new DeviceAuthorizationRequest(uri, clientID);

		assertThat(req.getEndpointURI()).isEqualTo(uri);
		assertThat(req.getClientID()).isEqualTo(clientID);

		assertThat(req.getScope()).isNull();

		assertThat(req.getCustomParameter("custom-param")).isNull();
		assertThat(req.getCustomParameters().isEmpty()).isTrue();

		HTTPRequest httpReq = req.toHTTPRequest();
		Map<String, List<String>> params = httpReq.getQueryParameters();
		assertThat(httpReq.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(httpReq.getURL().toURI()).isEqualTo(uri);
		assertThat(1).isEqualTo(params.size());

		req = DeviceAuthorizationRequest.parse(httpReq);

		assertThat(req.getEndpointURI()).isEqualTo(uri);
		assertThat(req.getClientID()).isEqualTo(clientID);

		assertThat(req.getScope()).isNull();

		assertThat(req.getCustomParameter("custom-param")).isNull();
		assertThat(req.getCustomParameters().isEmpty()).isTrue();
	}

	@Test
	public void testFull() throws Exception {

		URI uri = new URI("https://c2id.com/devauthz/");

		ClientID clientID = new ClientID("123456");
		Scope scope = Scope.parse("read write");

		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("x", Collections.singletonList("100"));
		customParams.put("y", Collections.singletonList("200"));
		customParams.put("z", Collections.singletonList("300"));

		DeviceAuthorizationRequest req = new DeviceAuthorizationRequest(uri, clientID, scope, customParams);

		assertThat(req.getEndpointURI()).isEqualTo(uri);
		assertThat(req.getClientID()).isEqualTo(clientID);
		assertThat(req.getScope()).isEqualTo(scope);

		HTTPRequest httpReq = req.toHTTPRequest();
		Map<String, List<String>> params = httpReq.getQueryParameters();
		assertThat(httpReq.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(params).hasSize(5);

		req = DeviceAuthorizationRequest.parse(httpReq);

		assertThat(req.getEndpointURI()).isEqualTo(uri);
		assertThat(req.getClientID()).isEqualTo(clientID);
		assertThat(req.getScope()).isEqualTo(scope);
		assertThat(req.getCustomParameter("x")).isEqualTo(Collections.singletonList("100"));
		assertThat(req.getCustomParameter("y")).isEqualTo(Collections.singletonList("200"));
		assertThat(req.getCustomParameter("z")).isEqualTo(Collections.singletonList("300"));
		assertThat(req.getCustomParameters().get("x")).isEqualTo(Collections.singletonList("100"));
		assertThat(req.getCustomParameters().get("y")).isEqualTo(Collections.singletonList("200"));
		assertThat(req.getCustomParameters().get("z")).isEqualTo(Collections.singletonList("300"));
		assertThat(req.getCustomParameters()).hasSize(3);
	}

	@Test
	public void testClientAuth() throws Exception {

		URI uri = new URI("https://c2id.com/devauthz/");

		ClientSecretBasic clientAuth = new ClientSecretBasic(new ClientID("123456"), new Secret("secret"));
		Scope scope = Scope.parse("read write");

		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("q", Collections.singletonList("abc"));
		customParams.put("r", Collections.singletonList("xyz"));

		DeviceAuthorizationRequest req = new DeviceAuthorizationRequest(uri, clientAuth, scope, customParams);

		assertThat(req.getEndpointURI()).isEqualTo(uri);
		assertThat(req.getClientAuthentication().getMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(req.getClientAuthentication().getClientID()).isEqualTo(clientAuth.getClientID());
		assertThat(((ClientSecretBasic) req.getClientAuthentication()).getClientSecret()).isEqualTo(clientAuth.getClientSecret());
		assertThat(req.getScope()).isEqualTo(scope);

		HTTPRequest httpReq = req.toHTTPRequest();
		Map<String, List<String>> params = httpReq.getQueryParameters();
		assertThat(httpReq.getMethod()).isEqualTo(HTTPRequest.Method.POST);
		assertThat(params).hasSize(3);

		req = DeviceAuthorizationRequest.parse(httpReq);

		assertThat(req.getEndpointURI()).isEqualTo(uri);
		assertThat(req.getClientAuthentication().getMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		assertThat(req.getClientAuthentication().getClientID()).isEqualTo(clientAuth.getClientID());
		assertThat(((ClientSecretBasic) req.getClientAuthentication()).getClientSecret()).isEqualTo(clientAuth.getClientSecret());
		assertThat(req.getScope()).isEqualTo(scope);
		assertThat(req.getCustomParameter("q")).isEqualTo(Collections.singletonList("abc"));
		assertThat(req.getCustomParameter("r")).isEqualTo(Collections.singletonList("xyz"));
		assertThat(req.getCustomParameters().get("q")).isEqualTo(Collections.singletonList("abc"));
		assertThat(req.getCustomParameters().get("r")).isEqualTo(Collections.singletonList("xyz"));
		assertThat(req.getCustomParameters()).hasSize(2);
	}

	@Test
	public void testBuilderMinimal() {

		DeviceAuthorizationRequest request = new DeviceAuthorizationRequest.Builder(new ClientID("123"))
		                .build();

		assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
		assertThat(request.getEndpointURI()).isNull();
		assertThat(request.getScope()).isNull();
		assertThat(request.getCustomParameters().isEmpty()).isTrue();
	}

	@Test
	public void testBuilderFull() throws Exception {

		DeviceAuthorizationRequest request = new DeviceAuthorizationRequest.Builder(new ClientID("123"))
		                .endpointURI(new URI("https://c2id.com/devauthz")).scope(new Scope("openid", "email"))
		                .build();

		assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
		assertThat(request.getEndpointURI().toString()).isEqualTo("https://c2id.com/devauthz");
		assertThat(request.getScope()).isEqualTo(new Scope("openid", "email"));
	}

	@Test
	public void testBuilderFullAlt() throws Exception {

		DeviceAuthorizationRequest request = new DeviceAuthorizationRequest.Builder(new ClientID("123"))
		                .endpointURI(new URI("https://c2id.com/devauthz")).scope(new Scope("openid", "email"))
		                .customParameter("x", "100").customParameter("y", "200").customParameter("z", "300")
		                .build();

		assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
		assertThat(request.getEndpointURI().toString()).isEqualTo("https://c2id.com/devauthz");
		assertThat(request.getScope()).isEqualTo(new Scope("openid", "email"));
		assertThat(request.getCustomParameter("x")).isEqualTo(Collections.singletonList("100"));
		assertThat(request.getCustomParameter("y")).isEqualTo(Collections.singletonList("200"));
		assertThat(request.getCustomParameter("z")).isEqualTo(Collections.singletonList("300"));
		assertThat(request.getCustomParameters().get("x")).isEqualTo(Collections.singletonList("100"));
		assertThat(request.getCustomParameters().get("y")).isEqualTo(Collections.singletonList("200"));
		assertThat(request.getCustomParameters().get("z")).isEqualTo(Collections.singletonList("300"));
		assertThat(request.getCustomParameters()).hasSize(3);
	}

	@Test
	public void testBuilderFullAuth() throws Exception {

		DeviceAuthorizationRequest request = new DeviceAuthorizationRequest.Builder(
		                new ClientSecretPost(new ClientID("123"), new Secret("secret")))
		                                .endpointURI(new URI("https://c2id.com/devauthz"))
		                                .scope(new Scope("openid", "email")).customParameter("x", "100")
		                                .customParameter("y", "200").customParameter("z", "300").build();

		assertThat(request.getClientAuthentication().getMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_POST);
		assertThat(request.getClientAuthentication().getClientID()).isEqualTo(new ClientID("123"));
		assertThat(request.getEndpointURI().toString()).isEqualTo("https://c2id.com/devauthz");
		assertThat(request.getScope()).isEqualTo(new Scope("openid", "email"));
		assertThat(request.getCustomParameter("x")).isEqualTo(Collections.singletonList("100"));
		assertThat(request.getCustomParameter("y")).isEqualTo(Collections.singletonList("200"));
		assertThat(request.getCustomParameter("z")).isEqualTo(Collections.singletonList("300"));
		assertThat(request.getCustomParameters().get("x")).isEqualTo(Collections.singletonList("100"));
		assertThat(request.getCustomParameters().get("y")).isEqualTo(Collections.singletonList("200"));
		assertThat(request.getCustomParameters().get("z")).isEqualTo(Collections.singletonList("300"));
		assertThat(request.getCustomParameters()).hasSize(3);
	}

	@Test
	public void testConstructParseExceptionMissingClientID() throws Exception {

		URI tokenEndpoint = new URI("https://c2id.com/devauthz");

		try {
			new DeviceAuthorizationRequest(tokenEndpoint, null);
			fail();
		} catch (IllegalArgumentException e) {
			assertThat(e.getMessage()).isEqualTo("The client ID must not be null");
		}

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST,
		                new URL("https://c2id.com/devauthz"));
		httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

		try {
			DeviceAuthorizationRequest.parse(httpRequest);
			fail();
		} catch (OAuth2JSONParseException e) {
			assertThat(e.getMessage()).isEqualTo("Missing \"client_id\" parameter");
			assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
			assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"client_id\" parameter");
			assertThat(e.getErrorObject().getURI()).isNull();
		}
	}

	@Test
	public void testCopyConstructorBuilder() throws Exception {

		Map<String, List<String>> customParams = new HashMap<>();
		customParams.put("apples", Collections.singletonList("10"));

		DeviceAuthorizationRequest in = new DeviceAuthorizationRequest(new URI("https://c2id.com/devauthz"),
		                new ClientID("123"), new Scope("openid"), customParams);

		DeviceAuthorizationRequest out = new DeviceAuthorizationRequest.Builder(in).build();

		assertThat(out.getScope()).isEqualTo(in.getScope());
		assertThat(out.getClientID()).isEqualTo(in.getClientID());
		assertThat(out.getCustomParameters()).isEqualTo(in.getCustomParameters());
		assertThat(out.getEndpointURI()).isEqualTo(in.getEndpointURI());
	}
}
