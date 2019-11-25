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


import be.atbash.ee.langtag.LangTag;
import be.atbash.ee.oauth2.sdk.GrantType;
import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.Scope;
import be.atbash.ee.oauth2.sdk.auth.ClientAuthenticationMethod;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.token.BearerTokenError;
import org.junit.Test;

import java.net.URI;
import java.net.URL;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the client update request class.
 */
public class ClientUpdateRequestTest  {
	
	@Test
	public void testParse()
		throws Exception {
		
		URI regURI = new URI("https://server.example.com/register/s6BhdRkqt3");
		
		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.PUT, regURI.toURL());
		httpRequest.setAuthorization("Bearer reg-23410913-abewfq.123483");
		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

		String json = "{\"client_id\":\"s6BhdRkqt3\","
			+ "    \"client_secret\": \"cf136dc3c1fc93f31185e5885805d\","
			+ "    \"redirect_uris\":[\"https://client.example.org/callback\",\"https://client.example.org/alt\"],"
			+ "    \"scope\": \"read write dolphin\","
			+ "    \"grant_types\": [\"authorization_code\", \"refresh_token\"],"
			+ "    \"token_endpoint_auth_method\": \"client_secret_basic\","
			+ "    \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\","
			+ "    \"client_name\":\"My New Example\","
			+ "    \"client_name#fr\":\"Mon Nouvel Exemple\","
			+ "    \"logo_uri\":\"https://client.example.org/newlogo.png\","
			+ "    \"logo_uri#fr\":\"https://client.example.org/fr/newlogo.png\""
			+ "   }";

		httpRequest.setQuery(json);
		
		ClientUpdateRequest request = ClientUpdateRequest.parse(httpRequest);
		
		assertThat(request.getEndpointURI()).isEqualTo(regURI);
		
		assertThat(request.getAccessToken().getValue()).isEqualTo("reg-23410913-abewfq.123483");
		
		assertThat(request.getClientID().getValue()).isEqualTo("s6BhdRkqt3");
		
		assertThat(request.getClientSecret().getValue()).isEqualTo("cf136dc3c1fc93f31185e5885805d");
		
		ClientMetadata metadata = request.getClientMetadata();
		
		Set<URI> redirectURIs = metadata.getRedirectionURIs();
		assertThat(redirectURIs).contains(new URI("https://client.example.org/callback"));
		assertThat(redirectURIs).contains(new URI("https://client.example.org/alt"));
		assertThat(redirectURIs).hasSize(2);
		
		assertThat(metadata.getScope()).isEqualTo(Scope.parse("read write dolphin"));
		
		Set<GrantType> grantTypes = metadata.getGrantTypes();
		assertThat(grantTypes).contains(GrantType.AUTHORIZATION_CODE);
		assertThat(grantTypes).contains(GrantType.REFRESH_TOKEN);
		assertThat(grantTypes).hasSize(2);
		
		assertThat(metadata.getTokenEndpointAuthMethod()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
		
		assertThat(metadata.getJWKSetURI()).isEqualTo(new URI("https://client.example.org/my_public_keys.jwks"));
		
		assertThat(metadata.getName()).isEqualTo("My New Example");
		assertThat(metadata.getName(null)).isEqualTo("My New Example");
		
		assertThat(metadata.getName(LangTag.parse("fr"))).isEqualTo("Mon Nouvel Exemple");
		
		assertThat(metadata.getNameEntries()).hasSize(2);
		
		assertThat(metadata.getLogoURI()).isEqualTo(new URI("https://client.example.org/newlogo.png"));
		assertThat(metadata.getLogoURI(null)).isEqualTo(new URI("https://client.example.org/newlogo.png"));
		
		assertThat(metadata.getLogoURI(LangTag.parse("fr"))).isEqualTo(new URI("https://client.example.org/fr/newlogo.png"));
		
		assertThat(metadata.getLogoURIEntries()).hasSize(2);
	}

	@Test
	public void testParseWithMissingAuthorizationHeader()
		throws Exception {

		HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.PUT, new URL("https://c2id.com/client-reg/123"));

		httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

		String json = "{\"client_id\":\"123\","
			+ "    \"client_secret\": \"cf136dc3c1fc93f31185e5885805d\","
			+ "    \"redirect_uris\":[\"https://client.example.org/callback\",\"https://client.example.org/alt\"],"
			+ "    \"scope\": \"read write dolphin\","
			+ "    \"grant_types\": [\"authorization_code\", \"refresh_token\"],"
			+ "    \"token_endpoint_auth_method\": \"client_secret_basic\","
			+ "    \"jwks_uri\": \"https://client.example.org/my_public_keys.jwks\","
			+ "    \"client_name\":\"My New Example\","
			+ "    \"client_name#fr\":\"Mon Nouvel Exemple\","
			+ "    \"logo_uri\":\"https://client.example.org/newlogo.png\","
			+ "    \"logo_uri#fr\":\"https://client.example.org/fr/newlogo.png\""
			+ "   }";

		httpRequest.setQuery(json);

		try {
			ClientUpdateRequest.parse(httpRequest);

			fail();

		} catch (OAuth2JSONParseException e) {

			assertThat(e.getErrorObject()).isInstanceOf(BearerTokenError.class);

			BearerTokenError bte = (BearerTokenError)e.getErrorObject();

			assertThat(bte.getHTTPStatusCode()).isEqualTo(401);
			assertThat(bte.getCode()).isNull();
			assertThat(bte.toWWWAuthenticateHeader()).isEqualTo("Bearer");
		}
	}
}