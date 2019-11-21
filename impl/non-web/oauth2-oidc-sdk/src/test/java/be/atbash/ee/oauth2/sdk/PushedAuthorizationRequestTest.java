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


import be.atbash.ee.oauth2.sdk.auth.ClientAuthentication;
import be.atbash.ee.oauth2.sdk.auth.ClientSecretBasic;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.openid.connect.sdk.AuthenticationRequest;
import be.atbash.ee.openid.connect.sdk.OIDCScopeValue;
import org.junit.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class PushedAuthorizationRequestTest {

    @Test
    public void testLifeCycle_clientSecretBasic_plainOAuth() throws OAuth2JSONParseException {

        URI endpoint = URI.create("https://c2id.com/par");
        ClientID clientID = new ClientID();
        Secret clientSecret = new Secret();
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), clientID)
                .scope(new Scope("read", "write"))
                .build();

        PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);
        assertThat(par.getEndpointURI()).isEqualTo(endpoint);
        assertThat(par.getClientAuthentication()).isEqualTo(clientAuth);
        assertThat(par.getAuthorizationRequest()).isEqualTo(authzRequest);

        HTTPRequest httpRequest = par.toHTTPRequest();
        assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
        assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
        assertThat(ClientSecretBasic.parse(httpRequest).getClientID()).isEqualTo(clientID);
        assertThat(ClientSecretBasic.parse(httpRequest).getClientSecret().getValue()).isEqualTo(clientSecret.getValue());
        assertThat(httpRequest.getQueryParameters().get("response_type")).isEqualTo(Collections.singletonList("code"));
        assertThat(httpRequest.getQueryParameters().get("client_id")).isEqualTo(Collections.singletonList(clientID.getValue()));
        assertThat(httpRequest.getQueryParameters().get("scope")).isEqualTo(Collections.singletonList("read write"));
        assertThat(httpRequest.getQueryParameters()).hasSize(3);

        par = PushedAuthorizationRequest.parse(httpRequest);
        assertThat(par.getEndpointURI()).isEqualTo(endpoint);
        assertThat(par.getClientAuthentication().getClientID()).isEqualTo(clientID);
        assertThat(((ClientSecretBasic) par.getClientAuthentication()).getClientSecret().getValue()).isEqualTo(clientSecret.getValue());
        assertThat(par.getAuthorizationRequest().toParameters()).isEqualTo(authzRequest.toParameters());
    }

    @Test
    public void testLifeCycle_clientSecretBasic_openID() throws OAuth2JSONParseException {

        URI endpoint = URI.create("https://c2id.com/par");
        ClientID clientID = new ClientID();
        Secret clientSecret = new Secret();
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        AuthorizationRequest authzRequest = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), new Scope(OIDCScopeValue.OPENID), clientID, URI.create("https://example.com/cb"))
                .build();

        PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);
        assertThat(par.getEndpointURI()).isEqualTo(endpoint);
        assertThat(par.getClientAuthentication()).isEqualTo(clientAuth);
        assertThat(par.getAuthorizationRequest()).isEqualTo(authzRequest);

        HTTPRequest httpRequest = par.toHTTPRequest();
        assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
        assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
        assertThat(ClientSecretBasic.parse(httpRequest).getClientID()).isEqualTo(clientID);
        assertThat(ClientSecretBasic.parse(httpRequest).getClientSecret().getValue()).isEqualTo(clientSecret.getValue());
        assertThat(httpRequest.getQueryParameters().get("response_type")).isEqualTo(Collections.singletonList("code"));
        assertThat(httpRequest.getQueryParameters().get("client_id")).isEqualTo(Collections.singletonList(clientID.getValue()));
        assertThat(httpRequest.getQueryParameters().get("scope")).isEqualTo(Collections.singletonList("openid"));
        assertThat(httpRequest.getQueryParameters().get("redirect_uri")).isEqualTo(Collections.singletonList("https://example.com/cb"));
        assertThat(httpRequest.getQueryParameters()).hasSize(4);

        par = PushedAuthorizationRequest.parse(httpRequest);
        assertThat(par.getEndpointURI()).isEqualTo(endpoint);
        assertThat(par.getClientAuthentication().getClientID()).isEqualTo(clientID);
        assertThat(((ClientSecretBasic) par.getClientAuthentication()).getClientSecret().getValue()).isEqualTo(clientSecret.getValue());
        assertThat(par.getAuthorizationRequest().toParameters()).isEqualTo(authzRequest.toParameters());
    }

    @Test
    public void testLifeCycle_publicClient_plainOAuth() throws OAuth2JSONParseException {

        URI endpoint = URI.create("https://c2id.com/par");
        ClientID clientID = new ClientID();
        AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), clientID)
                .scope(new Scope("read", "write"))
                .build();

        PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, authzRequest);
        assertThat(par.getEndpointURI()).isEqualTo(endpoint);
        assertThat(par.getClientAuthentication()).isNull();
        assertThat(par.getAuthorizationRequest()).isEqualTo(authzRequest);

        HTTPRequest httpRequest = par.toHTTPRequest();
        assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
        assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
        assertThat(httpRequest.getAuthorization()).isNull();
        assertThat(httpRequest.getQueryParameters().get("response_type")).isEqualTo(Collections.singletonList("code"));
        assertThat(httpRequest.getQueryParameters().get("client_id")).isEqualTo(Collections.singletonList(clientID.getValue()));
        assertThat(httpRequest.getQueryParameters().get("scope")).isEqualTo(Collections.singletonList("read write"));
        assertThat(httpRequest.getQueryParameters()).hasSize(3);

        par = PushedAuthorizationRequest.parse(httpRequest);
        assertThat(par.getEndpointURI()).isEqualTo(endpoint);
        assertThat(par.getClientAuthentication()).isNull();
        assertThat(par.getAuthorizationRequest().toParameters()).isEqualTo(authzRequest.toParameters());
    }

    @Test
    public void testEndpointOptional() {

        ClientID clientID = new ClientID();
        Secret clientSecret = new Secret();
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), clientID)
                .scope(new Scope("read", "write"))
                .build();

        PushedAuthorizationRequest par = new PushedAuthorizationRequest(null, clientAuth, authzRequest);
        assertThat(par.getEndpointURI()).isNull();
        assertThat(par.getClientAuthentication()).isEqualTo(clientAuth);
        assertThat(par.getAuthorizationRequest()).isEqualTo(authzRequest);
    }

    @Test
    public void testConfidentialClientConstructor_requireClientAuthentication() {

        try {
            new PushedAuthorizationRequest(
                    URI.create("https://c2id.com/par"),
                    null,
                    new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), new ClientID()).build());
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The client authentication must not be null");
        }
    }

    @Test
    public void testRequireAuthzRequest() {

        // confidential client
        try {
            new PushedAuthorizationRequest(
                    URI.create("https://c2id.com/par"),
                    new ClientSecretBasic(new ClientID(), new Secret()),
                    null);
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The authorization request must not be null");
        }

        // public client
        try {
            new PushedAuthorizationRequest(
                    URI.create("https://c2id.com/par"),
                    null);
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The authorization request must not be null");
        }
    }

    @Test
    public void testParseHTTPRequest_requirePOST() {

        try {
            PushedAuthorizationRequest.parse(new HTTPRequest(HTTPRequest.Method.GET, new URL("https://c2id.com/par")));
            fail();
        } catch (OAuth2JSONParseException | MalformedURLException e) {
            assertThat(e.getMessage()).isEqualTo("The HTTP request method must be POST");
        }
    }

    @Test
    public void testParseHTTPRequest_requireContentTypeHeader() throws OAuth2JSONParseException {

        URI endpoint = URI.create("https://c2id.com/par");
        ClientID clientID = new ClientID();
        Secret clientSecret = new Secret();
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), clientID)
                .scope(new Scope("read", "write"))
                .build();
        PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);
        HTTPRequest httpRequest = par.toHTTPRequest();

        // Remove encoding
        httpRequest.setContentType((String) null);

        try {
            PushedAuthorizationRequest.parse(httpRequest);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing HTTP Content-Type header");
        }
    }

    @Test
    public void testParseHTTPRequest_requireURLEncodedParams() {

        URI endpoint = URI.create("https://c2id.com/par");
        ClientID clientID = new ClientID();
        Secret clientSecret = new Secret();
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), clientID)
                .scope(new Scope("read", "write"))
                .build();
        PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);
        HTTPRequest httpRequest = par.toHTTPRequest();

        // Remove encoding
        httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);

        try {
            PushedAuthorizationRequest.parse(httpRequest);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("The HTTP Content-Type header must be application/x-www-form-urlencoded; charset=UTF-8");
        }
    }

    // client_id param optional in request body when found in client auth (authZ header)
    @Test
    public void testExtractClientIDFromClientSecretBasic() throws OAuth2JSONParseException {

        URI endpoint = URI.create("https://c2id.com/par");
        ClientID clientID = new ClientID();
        Secret clientSecret = new Secret();
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE), clientID)
                .scope(new Scope("read", "write"))
                .build();

        PushedAuthorizationRequest par = new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);

        HTTPRequest httpRequest = par.toHTTPRequest();

        Map<String, List<String>> params = httpRequest.getQueryParameters();
        params.remove("client_id"); // remove from body

        HTTPRequest modifiedHTTPRequest = new HTTPRequest(httpRequest.getMethod(), httpRequest.getURL());
        modifiedHTTPRequest.setContentType(httpRequest.getContentType());
        modifiedHTTPRequest.setAuthorization(httpRequest.getAuthorization());
        modifiedHTTPRequest.setQuery(URLUtils.serializeParameters(params));

        par = PushedAuthorizationRequest.parse(modifiedHTTPRequest);
        assertThat(par.getEndpointURI()).isEqualTo(endpoint);
        assertThat(par.getClientAuthentication().getClientID()).isEqualTo(clientID);
        assertThat(((ClientSecretBasic) par.getClientAuthentication()).getClientSecret().getValue()).isEqualTo(clientSecret.getValue());
        assertThat(par.getAuthorizationRequest().toParameters()).isEqualTo(authzRequest.toParameters());
    }

    @Test
    public void testRejectAuthorizationRequestWithRequestURI() {

        URI endpoint = URI.create("https://c2id.com/par");
        ClientID clientID = new ClientID();
        Secret clientSecret = new Secret();
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
                URI.create("https://example.com/eimeeph8"))
                .build();

        try {
            new PushedAuthorizationRequest(endpoint, clientAuth, authzRequest);
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("Authorization request_uri parameter not allowed");
        }

        try {
            new PushedAuthorizationRequest(endpoint, authzRequest);
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("Authorization request_uri parameter not allowed");
        }
    }

    @Test
    public void testParseRejectAuthorizationRequestWithRequestURI() throws MalformedURLException {

        URI endpoint = URI.create("https://c2id.com/par");
        ClientID clientID = new ClientID();
        Secret clientSecret = new Secret();
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);
        AuthorizationRequest authzRequest = new AuthorizationRequest.Builder(
                URI.create("https://example.com/eimeeph8"))
                .build();

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, endpoint.toURL());
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        clientAuth.applyTo(httpRequest);
        httpRequest.setQuery(authzRequest.toQueryString());

        try {
            PushedAuthorizationRequest.parse(httpRequest);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Authorization request_uri parameter not allowed");
            assertThat(e.getErrorObject().getHTTPStatusCode()).isEqualTo(400);
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Authorization request_uri parameter not allowed");
        }
    }
}
