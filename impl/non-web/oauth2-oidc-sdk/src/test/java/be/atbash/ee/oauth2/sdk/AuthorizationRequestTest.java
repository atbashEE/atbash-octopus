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


import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.pkce.CodeChallenge;
import be.atbash.ee.oauth2.sdk.pkce.CodeChallengeMethod;
import be.atbash.ee.oauth2.sdk.pkce.CodeVerifier;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.openid.connect.sdk.Prompt;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.PlainJWT;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLEncoder;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class AuthorizationRequestTest {

    @Test
    public void testRegisteredParameters() {

        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("response_type");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("response_mode");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("client_id");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("redirect_uri");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("scope");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("state");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("code_challenge");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("code_challenge_method");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("resource");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("include_granted_scopes");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("request");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("request_uri");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).contains("prompt");
        assertThat(AuthorizationRequest.getRegisteredParameterNames()).hasSize(13);
    }

    @Test
    public void testMinimal()
            throws Exception {

        URI uri = new URI("https://c2id.com/authz/");

        ResponseType rts = new ResponseType();
        rts.add(ResponseType.Value.CODE);

        ClientID clientID = new ClientID("123456");

        AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);

        assertThat(req.getEndpointURI()).isEqualTo(uri);
        assertThat(req.getResponseType()).isEqualTo(rts);
        assertThat(req.getClientID()).isEqualTo(clientID);

        assertThat(req.getRedirectionURI()).isNull();
        assertThat(req.getScope()).isNull();
        assertThat(req.getState()).isNull();
        assertThat(req.getResponseMode()).isNull();
        assertThat(req.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);

        assertThat(req.getResources()).isNull();

        assertThat(req.includeGrantedScopes()).isFalse();

        assertThat(req.getCustomParameter("custom-param")).isNull();
        assertThat(req.getCustomParameters().isEmpty()).isTrue();

        String query = req.toQueryString();

        System.out.println("Authorization query: " + query);

        Map<String, List<String>> params = URLUtils.parseParameters(query);
        assertThat(params.get("response_type")).isEqualTo(Collections.singletonList("code"));
        assertThat(params.get("client_id")).isEqualTo(Collections.singletonList("123456"));
        assertThat(params).hasSize(2);

        HTTPRequest httpReq = req.toHTTPRequest();
        assertThat(httpReq.getMethod()).isEqualTo(HTTPRequest.Method.GET);
        assertThat(httpReq.getURL().toURI()).isEqualTo(uri);
        assertThat(httpReq.getQuery()).isEqualTo(query);

        req = AuthorizationRequest.parse(uri, query);

        assertThat(req.getEndpointURI()).isEqualTo(uri);
        assertThat(req.getResponseType()).isEqualTo(rts);
        assertThat(req.getClientID()).isEqualTo(clientID);

        assertThat(req.getResponseMode()).isNull();
        assertThat(req.getRedirectionURI()).isNull();
        assertThat(req.getScope()).isNull();
        assertThat(req.getState()).isNull();
        assertThat(req.getResponseMode()).isNull();
        assertThat(req.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(req.getResources()).isNull();
        assertThat(req.includeGrantedScopes()).isFalse();

        assertThat(req.getCustomParameter("custom-param")).isNull();
        assertThat(req.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testMinimalAltParse()
            throws Exception {

        URI uri = new URI("https://c2id.com/authz/");

        ResponseType rts = new ResponseType();
        rts.add(ResponseType.Value.CODE);

        ClientID clientID = new ClientID("123456");

        AuthorizationRequest req = new AuthorizationRequest(uri, rts, clientID);

        String query = req.toQueryString();

        req = AuthorizationRequest.parse(query);

        assertThat(req.getEndpointURI()).isNull();
        assertThat(req.getResponseType()).isEqualTo(rts);
        assertThat(req.getClientID()).isEqualTo(clientID);
        assertThat(req.getResponseMode()).isNull();
        assertThat(req.getRedirectionURI()).isNull();
        assertThat(req.getScope()).isNull();
        assertThat(req.getState()).isNull();
        assertThat(req.getResponseMode()).isNull();
        assertThat(req.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(req.getResources()).isNull();
        assertThat(req.includeGrantedScopes()).isFalse();
        assertThat(req.getCustomParameter("custom-param")).isNull();
        assertThat(req.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testToRequestURIWithParse()
            throws Exception {

        URI redirectURI = new URI("https://client.com/cb");
        ResponseType rts = new ResponseType("code");
        ClientID clientID = new ClientID("123456");
        URI endpointURI = new URI("https://c2id.com/login");

        AuthorizationRequest req = new AuthorizationRequest.Builder(rts, clientID).
                redirectionURI(redirectURI).
                endpointURI(endpointURI).
                build();

        URI requestURI = req.toURI();

        assertThat(requestURI.toString().startsWith(endpointURI.toString() + "?")).isTrue();
        req = AuthorizationRequest.parse(requestURI);

        assertThat(req.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(req.getResponseType()).isEqualTo(rts);
        assertThat(req.getClientID()).isEqualTo(clientID);
        assertThat(req.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(req.getResponseMode()).isNull();
        assertThat(req.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(req.getScope()).isNull();
        assertThat(req.getState()).isNull();
        assertThat(req.getResources()).isNull();
        assertThat(req.includeGrantedScopes()).isFalse();
        assertThat(req.getCustomParameter("custom-param")).isNull();
        assertThat(req.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testFull()
            throws Exception {

        URI uri = new URI("https://c2id.com/authz/");

        ResponseType rts = new ResponseType();
        rts.add(ResponseType.Value.CODE);

        ResponseMode rm = ResponseMode.FORM_POST;

        ClientID clientID = new ClientID("123456");

        URI redirectURI = new URI("https://example.com/oauth2/");

        Scope scope = Scope.parse("read write");

        State state = new State();

        CodeVerifier codeVerifier = new CodeVerifier();
        CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
        CodeChallenge codeChallenge = CodeChallenge.compute(codeChallengeMethod, codeVerifier);

        List<URI> resources = Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com"));

        Prompt prompt = new Prompt(Prompt.Type.LOGIN);

        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("x", Collections.singletonList("100"));
        customParams.put("y", Collections.singletonList("200"));
        customParams.put("z", Collections.singletonList("300"));


        AuthorizationRequest req = new AuthorizationRequest(uri, rts, rm, clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, resources, true, null, null, prompt, customParams);

        assertThat(req.getEndpointURI()).isEqualTo(uri);
        assertThat(req.getResponseType()).isEqualTo(rts);
        assertThat(req.getResponseMode()).isEqualTo(rm);
        assertThat(req.impliedResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(req.getClientID()).isEqualTo(clientID);
        assertThat(req.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(req.getScope()).isEqualTo(scope);
        assertThat(req.getState()).isEqualTo(state);
        assertThat(req.getResources()).isEqualTo(resources);
        assertThat(req.getPrompt()).isEqualTo(prompt);

        String query = req.toQueryString();

        System.out.println("Authorization query: " + query);

        Map<String, List<String>> params = URLUtils.parseParameters(query);

        assertThat(params.get("response_type")).isEqualTo(Collections.singletonList("code"));
        assertThat(params.get("response_mode")).isEqualTo(Collections.singletonList("form_post"));
        assertThat(params.get("client_id")).isEqualTo(Collections.singletonList("123456"));
        assertThat(params.get("redirect_uri")).isEqualTo(Collections.singletonList(redirectURI.toString()));
        assertThat(params.get("scope")).isEqualTo(Collections.singletonList(scope.toString()));
        assertThat(params.get("state")).isEqualTo(Collections.singletonList(state.getValue()));
        assertThat(params.get("code_challenge")).isEqualTo(Collections.singletonList(codeChallenge.getValue()));
        assertThat(params.get("code_challenge_method")).isEqualTo(Collections.singletonList(codeChallengeMethod.getValue()));
        assertThat(params.get("resource")).isEqualTo(Arrays.asList("https://rs1.com", "https://rs2.com"));
        assertThat(params.get("prompt")).isEqualTo(Collections.singletonList(prompt.toString()));
        assertThat(params.get("include_granted_scopes")).isEqualTo(Collections.singletonList("true"));
        assertThat(params.get("x")).isEqualTo(Collections.singletonList("100"));
        assertThat(params.get("y")).isEqualTo(Collections.singletonList("200"));
        assertThat(params.get("z")).isEqualTo(Collections.singletonList("300"));
        assertThat(params).hasSize(14);

        HTTPRequest httpReq = req.toHTTPRequest();
        assertThat(httpReq.getMethod()).isEqualTo(HTTPRequest.Method.GET);
        assertThat(httpReq.getQuery()).isEqualTo(query);

        req = AuthorizationRequest.parse(uri, query);

        assertThat(req.getEndpointURI()).isEqualTo(uri);
        assertThat(req.getResponseType()).isEqualTo(rts);
        assertThat(req.getResponseMode()).isEqualTo(rm);
        assertThat(req.impliedResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(req.getClientID()).isEqualTo(clientID);
        assertThat(req.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(req.getScope()).isEqualTo(scope);
        assertThat(req.getState()).isEqualTo(state);
        assertThat(req.getCodeChallenge()).isEqualTo(codeChallenge);
        assertThat(req.getCodeChallengeMethod()).isEqualTo(codeChallengeMethod);
        assertThat(req.getResources()).isEqualTo(resources);
        assertThat(req.includeGrantedScopes()).isTrue();
        assertThat(req.getPrompt()).isEqualTo(prompt);
        assertThat(req.getCustomParameter("x")).isEqualTo(Collections.singletonList("100"));
        assertThat(req.getCustomParameter("y")).isEqualTo(Collections.singletonList("200"));
        assertThat(req.getCustomParameter("z")).isEqualTo(Collections.singletonList("300"));
        assertThat(req.getCustomParameters().get("x")).isEqualTo(Collections.singletonList("100"));
        assertThat(req.getCustomParameters().get("y")).isEqualTo(Collections.singletonList("200"));
        assertThat(req.getCustomParameters().get("z")).isEqualTo(Collections.singletonList("300"));
        assertThat(req.getCustomParameters()).hasSize(3);
    }

    @Test
    public void testFullAltParse()
            throws Exception {

        URI uri = new URI("https://c2id.com/authz/");
        ResponseType rts = new ResponseType();
        rts.add(ResponseType.Value.CODE);

        ClientID clientID = new ClientID("123456");

        URI redirectURI = new URI("https://example.com/oauth2/");

        Scope scope = Scope.parse("read write");

        State state = new State();

        CodeVerifier verifier = new CodeVerifier();
        CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.PLAIN, verifier);

        List<URI> resources = Collections.singletonList(URI.create("https://rs1.com"));

        AuthorizationRequest req = new AuthorizationRequest(uri, rts, null, clientID, redirectURI, scope, state, codeChallenge, null, resources, false, null, null, null, null);

        assertThat(req.getEndpointURI()).isEqualTo(uri);
        assertThat(req.getResponseType()).isEqualTo(rts);
        assertThat(req.getResponseMode()).isNull();
        assertThat(req.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(req.getClientID()).isEqualTo(clientID);
        assertThat(req.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(req.getScope()).isEqualTo(scope);
        assertThat(req.getState()).isEqualTo(state);
        assertThat(req.getResources()).isEqualTo(resources);
        assertThat(req.getPrompt()).isNull();

        String query = req.toQueryString();

        req = AuthorizationRequest.parse(query);

        assertThat(req.getEndpointURI()).isNull();
        assertThat(req.getResponseType()).isEqualTo(rts);
        assertThat(req.getResponseMode()).isNull();
        assertThat(req.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(req.getClientID()).isEqualTo(clientID);
        assertThat(req.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(req.getScope()).isEqualTo(scope);
        assertThat(req.getState()).isEqualTo(state);
        assertThat(req.getCodeChallenge()).isEqualTo(codeChallenge);
        assertThat(req.getResources()).isEqualTo(resources);
        assertThat(req.includeGrantedScopes()).isFalse();
        assertThat(req.getCodeChallengeMethod()).isNull();
    }

    @Test
    public void testBuilderMinimal() {

        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123")).build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI()).isNull();
        assertThat(request.getRedirectionURI()).isNull();
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(request.getScope()).isNull();
        assertThat(request.getState()).isNull();
        assertThat(request.getCodeChallenge()).isNull();
        assertThat(request.getCodeChallengeMethod()).isNull();
        assertThat(request.getResources()).isNull();
        assertThat(request.includeGrantedScopes()).isFalse();
        assertThat(request.getPrompt()).isNull();
        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }


    public void testBuilderMinimalAlt() {

        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("token"), new ClientID("123")).build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("token"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI()).isNull();
        assertThat(request.getRedirectionURI()).isNull();
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
        assertThat(request.getScope()).isNull();
        assertThat(request.getState()).isNull();
        assertThat(request.getCodeChallenge()).isNull();
        assertThat(request.getCodeChallengeMethod()).isNull();
        assertThat(request.includeGrantedScopes()).isFalse();
        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testBuilderMinimalNullCodeChallenge() {

        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("token"), new ClientID("123"))
                .codeChallenge((CodeVerifier) null, null)
                .build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("token"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI()).isNull();
        assertThat(request.getRedirectionURI()).isNull();
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
        assertThat(request.getScope()).isNull();
        assertThat(request.getState()).isNull();
        assertThat(request.getCodeChallenge()).isNull();
        assertThat(request.getCodeChallengeMethod()).isNull();
        assertThat(request.includeGrantedScopes()).isFalse();
        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testBuilderMinimalNullCodeChallenge_deprecated() {

        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("token"), new ClientID("123"))
                .codeChallenge((CodeChallenge) null, null)
                .build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("token"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI()).isNull();
        assertThat(request.getRedirectionURI()).isNull();
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
        assertThat(request.getScope()).isNull();
        assertThat(request.getState()).isNull();
        assertThat(request.getCodeChallenge()).isNull();
        assertThat(request.getCodeChallengeMethod()).isNull();
        assertThat(request.includeGrantedScopes()).isFalse();
        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testBuilderFull()
            throws Exception {

        CodeVerifier codeVerifier = new CodeVerifier();

        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
                .endpointURI(new URI("https://c2id.com/login"))
                .redirectionURI(new URI("https://client.com/cb"))
                .scope(new Scope("openid", "email"))
                .state(new State("123"))
                .responseMode(ResponseMode.FORM_POST)
                .codeChallenge(codeVerifier, CodeChallengeMethod.S256)
                .resources(URI.create("https://rs1.com"), URI.create("https://rs2.com"))
                .includeGrantedScopes(true)
                .prompt(new Prompt(Prompt.Type.LOGIN))
                .build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(request.getResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI().toString()).isEqualTo("https://c2id.com/login");
        assertThat(request.getRedirectionURI().toString()).isEqualTo("https://client.com/cb");
        assertThat(request.getScope()).isEqualTo(new Scope("openid", "email"));
        assertThat(request.getState()).isEqualTo(new State("123"));
        assertThat(request.getCodeChallenge()).isEqualTo(CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier));
        assertThat(request.getCodeChallengeMethod()).isEqualTo(CodeChallengeMethod.S256);
        assertThat(request.getResources()).isEqualTo(Arrays.asList(URI.create("https://rs1.com"), URI.create("https://rs2.com")));
        assertThat(request.includeGrantedScopes()).isTrue();
        assertThat(request.getPrompt()).isEqualTo(new Prompt(Prompt.Type.LOGIN));
    }

    @Test
    public void testBuilderFullAlt()
            throws Exception {

        CodeVerifier codeVerifier = new CodeVerifier();

        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
                .endpointURI(new URI("https://c2id.com/login"))
                .redirectionURI(new URI("https://client.com/cb"))
                .scope(new Scope("openid", "email"))
                .state(new State("123"))
                .responseMode(ResponseMode.FORM_POST)
                .codeChallenge(codeVerifier, null)
                .resources(URI.create("https://rs1.com"))
                .includeGrantedScopes(false)
                .customParameter("x", "100")
                .customParameter("y", "200")
                .customParameter("z", "300")
                .build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(request.getResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI().toString()).isEqualTo("https://c2id.com/login");
        assertThat(request.getRedirectionURI().toString()).isEqualTo("https://client.com/cb");
        assertThat(request.getScope()).isEqualTo(new Scope("openid", "email"));
        assertThat(request.getState()).isEqualTo(new State("123"));
        assertThat(request.getCodeChallenge()).isEqualTo(CodeChallenge.compute(CodeChallengeMethod.PLAIN, codeVerifier));
        assertThat(request.getCodeChallengeMethod()).isEqualTo(CodeChallengeMethod.PLAIN);
        assertThat(request.getResources()).isEqualTo(Collections.singletonList(URI.create("https://rs1.com")));
        assertThat(request.includeGrantedScopes()).isFalse();
        assertThat(request.getCustomParameter("x")).isEqualTo(Collections.singletonList("100"));
        assertThat(request.getCustomParameter("y")).isEqualTo(Collections.singletonList("200"));
        assertThat(request.getCustomParameter("z")).isEqualTo(Collections.singletonList("300"));
        assertThat(request.getCustomParameters().get("x")).isEqualTo(Collections.singletonList("100"));
        assertThat(request.getCustomParameters().get("y")).isEqualTo(Collections.singletonList("200"));
        assertThat(request.getCustomParameters().get("z")).isEqualTo(Collections.singletonList("300"));
        assertThat(request.getCustomParameters()).hasSize(3);
    }

    @Test
    public void testBuilderFull_codeChallengeDeprecated()
            throws Exception {

        CodeVerifier codeVerifier = new CodeVerifier();
        CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);

        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123")).
                endpointURI(new URI("https://c2id.com/login")).
                redirectionURI(new URI("https://client.com/cb")).
                scope(new Scope("openid", "email")).
                state(new State("123")).
                responseMode(ResponseMode.FORM_POST).
                codeChallenge(codeChallenge, CodeChallengeMethod.S256).
                build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(request.getResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI().toString()).isEqualTo("https://c2id.com/login");
        assertThat(request.getRedirectionURI().toString()).isEqualTo("https://client.com/cb");
        assertThat(request.getScope()).isEqualTo(new Scope("openid", "email"));
        assertThat(request.getState()).isEqualTo(new State("123"));
        assertThat(request.getCodeChallenge()).isEqualTo(codeChallenge);
        assertThat(request.getCodeChallengeMethod()).isEqualTo(CodeChallengeMethod.S256);
    }

    @Test
    public void testBuilderFullAlt_codeChallengeDeprecated()
            throws Exception {

        CodeVerifier codeVerifier = new CodeVerifier();
        CodeChallenge codeChallenge = CodeChallenge.compute(CodeChallengeMethod.PLAIN, codeVerifier);


        AuthorizationRequest request = new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
                .endpointURI(new URI("https://c2id.com/login"))
                .redirectionURI(new URI("https://client.com/cb"))
                .scope(new Scope("openid", "email"))
                .state(new State("123"))
                .responseMode(ResponseMode.FORM_POST)
                .codeChallenge(codeChallenge, null)
                .customParameter("x", "100")
                .customParameter("y", "200")
                .customParameter("z", "300")
                .build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(request.getResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI().toString()).isEqualTo("https://c2id.com/login");
        assertThat(request.getRedirectionURI().toString()).isEqualTo("https://client.com/cb");
        assertThat(request.getScope()).isEqualTo(new Scope("openid", "email"));
        assertThat(request.getState()).isEqualTo(new State("123"));
        assertThat(request.getCodeChallenge()).isEqualTo(codeChallenge);
        assertThat(request.getCodeChallengeMethod()).isNull();
        assertThat(request.getCustomParameter("x")).isEqualTo(Collections.singletonList("100"));
        assertThat(request.getCustomParameter("y")).isEqualTo(Collections.singletonList("200"));
        assertThat(request.getCustomParameter("z")).isEqualTo(Collections.singletonList("300"));
        assertThat(request.getCustomParameters().get("x")).isEqualTo(Collections.singletonList("100"));
        assertThat(request.getCustomParameters().get("y")).isEqualTo(Collections.singletonList("200"));
        assertThat(request.getCustomParameters().get("z")).isEqualTo(Collections.singletonList("300"));
        assertThat(request.getCustomParameters()).hasSize(3);
    }

    @Test
    public void testParseExceptionMissingClientID()
            throws Exception {

        URI requestURI = new URI("https://server.example.com/authorize?" +
                "response_type=code" +
                "&state=xyz" +
                "&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

        try {
            AuthorizationRequest.parse(requestURI);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing \"client_id\" parameter");
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"client_id\" parameter");
            assertThat(e.getErrorObject().getURI()).isNull();
        }
    }

    @Test
    public void testParseExceptionInvalidRedirectionURI()
            throws Exception {

        URI requestURI = new URI("https://server.example.com/authorize?" +
                "response_type=code" +
                "&client_id=s6BhdRkqt3" +
                "&state=xyz" +
                "&redirect_uri=%3A");

        try {
            AuthorizationRequest.parse(requestURI);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage().startsWith("Invalid \"redirect_uri\" parameter")).isTrue();
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription().startsWith("Invalid request: Invalid \"redirect_uri\" parameter")).isTrue();
            assertThat(e.getErrorObject().getURI()).isNull();
        }
    }

    @Test
    public void testParseExceptionMissingResponseType()
            throws Exception {

        URI requestURI = new URI("https://server.example.com/authorize?" +
                "response_type=" +
                "&client_id=123" +
                "&state=xyz" +
                "&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb");

        try {
            AuthorizationRequest.parse(requestURI);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing \"response_type\" parameter");
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"response_type\" parameter");
            assertThat(e.getErrorObject().getURI()).isNull();
        }
    }


    // See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
    @Test
    public void testParseWithEncodedEqualsChar()
            throws Exception {

        URI redirectURI = URI.create("https://client.com/in?app=123");

        String encodedRedirectURI = URLEncoder.encode(redirectURI.toString(), "UTF-8");

        URI requestURI = URI.create("https://server.example.com/authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=" +
                encodedRedirectURI);

        AuthorizationRequest request = AuthorizationRequest.parse(requestURI);

        assertThat(request.getResponseType()).isEqualTo(ResponseType.parse("code"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("s6BhdRkqt3"));
        assertThat(request.getState()).isEqualTo(new State("xyz"));
        assertThat(request.getRedirectionURI()).isEqualTo(redirectURI);
    }

    @Test
    public void testCopyConstructorBuilder()
            throws Exception {

        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("apples", Collections.singletonList("10"));

        AuthorizationRequest in = new AuthorizationRequest(
                new URI("https://example.com/cb"),
                new ResponseType("code"),
                ResponseMode.FORM_POST,
                new ClientID("123"),
                new URI("https://example.com/cb"),
                new Scope("openid"),
                new State(),
                CodeChallenge.compute(CodeChallengeMethod.S256, new CodeVerifier()),
                CodeChallengeMethod.S256,
                Collections.singletonList(URI.create("https://rs1.com")),
                true,
                null,
                null,
                new Prompt(Prompt.Type.LOGIN, Prompt.Type.CONSENT),
                customParams);

        AuthorizationRequest out = new AuthorizationRequest.Builder(in).build();

        assertThat(out.getResponseType()).isEqualTo(in.getResponseType());
        assertThat(out.getScope()).isEqualTo(in.getScope());
        assertThat(out.getClientID()).isEqualTo(in.getClientID());
        assertThat(out.getRedirectionURI()).isEqualTo(in.getRedirectionURI());
        assertThat(out.getState()).isEqualTo(in.getState());
        assertThat(out.getResponseMode()).isEqualTo(in.getResponseMode());
        assertThat(out.getCodeChallenge()).isEqualTo(in.getCodeChallenge());
        assertThat(out.getCodeChallengeMethod()).isEqualTo(in.getCodeChallengeMethod());
        assertThat(out.getResources()).isEqualTo(in.getResources());
        assertThat(out.includeGrantedScopes()).isEqualTo(in.includeGrantedScopes());
        assertThat(out.getPrompt()).isEqualTo(in.getPrompt());
        assertThat(out.getCustomParameters()).isEqualTo(in.getCustomParameters());
        assertThat(out.getEndpointURI()).isEqualTo(in.getEndpointURI());
    }

    @Test
    public void testQueryParamsInEndpoint()
            throws Exception {

        URI endpoint = new URI("https://c2id.com/login?foo=bar");

        AuthorizationRequest request = new AuthorizationRequest(endpoint, new ResponseType(ResponseType.Value.CODE), new ClientID("123"));

        // query parameters belonging to the authz endpoint not included here
        Map<String, List<String>> requestParameters = request.toParameters();
        assertThat(requestParameters.get("response_type")).isEqualTo(Collections.singletonList("code"));
        assertThat(requestParameters.get("client_id")).isEqualTo(Collections.singletonList("123"));
        assertThat(requestParameters).hasSize(2);

        Map<String, List<String>> queryParams = URLUtils.parseParameters(request.toQueryString());
        assertThat(queryParams.get("foo")).isEqualTo(Collections.singletonList("bar"));
        assertThat(queryParams.get("response_type")).isEqualTo(Collections.singletonList("code"));
        assertThat(queryParams.get("client_id")).isEqualTo(Collections.singletonList("123"));
        assertThat(queryParams).hasSize(3);

        URI redirectToAS = request.toURI();

        Map<String, List<String>> finalParameters = URLUtils.parseParameters(redirectToAS.getQuery());
        assertThat(finalParameters.get("foo")).isEqualTo(Collections.singletonList("bar"));
        assertThat(finalParameters.get("response_type")).isEqualTo(Collections.singletonList("code"));
        assertThat(finalParameters.get("client_id")).isEqualTo(Collections.singletonList("123"));
        assertThat(finalParameters).hasSize(3);
    }

    @Test
    public void testBuilderWithResource_rejectNonAbsoluteURI() {

        try {
            new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
                    .resources(URI.create("https:///api/v1"))
                    .build();
            fail();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo("Resource URI must be absolute and with no query or fragment: https:///api/v1");
        }
    }

    @Test
    public void testBuilderWithResource_rejectURIWithQuery() {

        try {
            new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
                    .resources(URI.create("https://rs1.com/api/v1?query"))
                    .build();
            fail();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo("Resource URI must be absolute and with no query or fragment: https://rs1.com/api/v1?query");
        }
    }

    @Test
    public void testBuilderWithResource_rejectURIWithFragment() {

        try {
            new AuthorizationRequest.Builder(new ResponseType("code"), new ClientID("123"))
                    .resources(URI.create("https://rs1.com/api/v1#fragment"))
                    .build();
            fail();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo("Resource URI must be absolute and with no query or fragment: https://rs1.com/api/v1#fragment");
        }
    }

    @Test
    public void testParseResourceIndicatorsExample()
            throws OAuth2JSONParseException {

        AuthorizationRequest request = AuthorizationRequest.parse(
                URI.create(
                        "https://authorization-server.example.com" +
                                "/as/authorization.oauth2?response_type=token" +
                                "&client_id=s6BhdRkqt3&state=laeb" +
                                "&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
                                "&resource=https%3A%2F%2Frs.example.com%2F"));

        assertThat(request.getClientID()).isEqualTo(new ClientID("s6BhdRkqt3"));
        assertThat(request.getState()).isEqualTo(new State("laeb"));
        assertThat(request.getResponseType()).isEqualTo(new ResponseType("token"));
        assertThat(request.getRedirectionURI()).isEqualTo(URI.create("https://client.example.com/cb"));
        assertThat(request.getResources()).isEqualTo(Collections.singletonList(URI.create("https://rs.example.com/")));
    }

    @Test
    public void testParse_rejectResourceURIWithHostNotAbsolute() {

        try {
            AuthorizationRequest.parse(URI.create("https://authorization-server.example.com" +
                    "/as/authorization.oauth2?response_type=token" +
                    "&client_id=s6BhdRkqt3&state=laeb" +
                    "&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
                    "&resource=https%3A%2F%2F%2F"));
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_RESOURCE);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid \"resource\" parameter: Must be an absolute URI and with no query or fragment: https:///");
        }
    }

    @Test
    public void testParse_rejectResourceURIWithQuery()
            throws UnsupportedEncodingException {

        try {
            AuthorizationRequest.parse(URI.create("https://authorization-server.example.com" +
                    "/as/authorization.oauth2?response_type=token" +
                    "&client_id=s6BhdRkqt3&state=laeb" +
                    "&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
                    "&resource=" + URLEncoder.encode("https://rs.example.com/?query", "utf-8")));
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_RESOURCE);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid \"resource\" parameter: Must be an absolute URI and with no query or fragment: https://rs.example.com/?query");
        }
    }

    @Test
    public void testParse_rejectResourceURIWithFragment()
            throws UnsupportedEncodingException {

        try {
            AuthorizationRequest.parse(URI.create("https://authorization-server.example.com" +
                    "/as/authorization.oauth2?response_type=token" +
                    "&client_id=s6BhdRkqt3&state=laeb" +
                    "&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb" +
                    "&resource=" + URLEncoder.encode("https://rs.example.com/#fragment", "utf-8")));
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_RESOURCE);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid \"resource\" parameter: Must be an absolute URI and with no query or fragment: https://rs.example.com/#fragment");
        }
    }

    @Test
    public void testImpliedResponseMode_JARM_JWT() {

        assertThat(new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), new ClientID("123"))
                .responseMode(ResponseMode.JWT)
                .build()
                .impliedResponseMode()).isEqualTo(ResponseMode.QUERY_JWT);

        assertThat(new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.CODE), new ClientID("123"))
                .responseMode(ResponseMode.QUERY_JWT)
                .build()
                .impliedResponseMode()).isEqualTo(ResponseMode.QUERY_JWT);

        assertThat(new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.TOKEN), new ClientID("123"))
                .responseMode(ResponseMode.JWT)
                .build()
                .impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT_JWT);

        assertThat(new AuthorizationRequest.Builder(new ResponseType(ResponseType.Value.TOKEN), new ClientID("123"))
                .responseMode(ResponseMode.FRAGMENT_JWT)
                .build()
                .impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT_JWT);
    }

    @Test
    public void testToJWTClaimsSet() throws java.text.ParseException {

        AuthorizationRequest ar = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                new ClientID("123"))
                .redirectionURI(URI.create("https://example.com/cb"))
                .state(new State())
                .build();

        JWTClaimsSet jwtClaimsSet = ar.toJWTClaimsSet();

        assertThat(jwtClaimsSet.getStringClaim("response_type")).isEqualTo(ar.getResponseType().toString());
        assertThat(jwtClaimsSet.getStringClaim("client_id")).isEqualTo(ar.getClientID().toString());
        assertThat(jwtClaimsSet.getStringClaim("redirect_uri")).isEqualTo(ar.getRedirectionURI().toString());
        assertThat(jwtClaimsSet.getStringClaim("state")).isEqualTo(ar.getState().toString());

        assertThat(jwtClaimsSet.getClaims()).hasSize(4);
    }

    @Test
    public void testToJWTClaimsSet_multipleResourceParams() throws java.text.ParseException {

        AuthorizationRequest ar = new AuthorizationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                new ClientID("123"))
                .redirectionURI(URI.create("https://example.com/cb"))
                .state(new State())
                .resources(URI.create("https://one.rs.com"), URI.create("https://two.rs.com"))
                .build();

        JWTClaimsSet jwtClaimsSet = ar.toJWTClaimsSet();

        assertThat(jwtClaimsSet.getStringClaim("response_type")).isEqualTo(ar.getResponseType().toString());
        assertThat(jwtClaimsSet.getStringClaim("client_id")).isEqualTo(ar.getClientID().toString());
        assertThat(jwtClaimsSet.getStringClaim("redirect_uri")).isEqualTo(ar.getRedirectionURI().toString());
        assertThat(jwtClaimsSet.getStringClaim("state")).isEqualTo(ar.getState().toString());
        assertThat(jwtClaimsSet.getStringListClaim("resource").get(0)).isEqualTo(ar.getResources().get(0).toString());
        assertThat(jwtClaimsSet.getStringListClaim("resource").get(1)).isEqualTo(ar.getResources().get(1).toString());
        assertThat(jwtClaimsSet.getStringListClaim("resource")).hasSize(ar.getResources().size());

        assertThat(jwtClaimsSet.getClaims()).hasSize(5);
    }

    @Test
    public void testJAR_requestURI_only()
            throws OAuth2JSONParseException {

        URI endpointURI = URI.create("https://c2id.com/login");
        URI requestURI = URI.create("urn:requests:ahy4ohgo");

        AuthorizationRequest ar = new AuthorizationRequest.Builder(requestURI)
                .endpointURI(endpointURI)
                .build();

        assertThat(ar.getResponseType()).isNull();
        assertThat(ar.getClientID()).isNull();
        assertThat(ar.getRedirectionURI()).isNull();
        assertThat(ar.getScope()).isNull();
        assertThat(ar.getState()).isNull();
        assertThat(ar.getResponseMode()).isNull();
        assertThat(ar.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(ar.getResources()).isNull();
        assertThat(ar.includeGrantedScopes()).isFalse();
        assertThat(ar.getCustomParameter("custom-param")).isNull();
        assertThat(ar.getCustomParameters().isEmpty()).isTrue();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isEqualTo(requestURI);
        assertThat(ar.getRequestObject()).isNull();
        assertThat(ar.specifiesRequestObject()).isTrue();

        assertThat(ar.toQueryString()).isEqualTo("request_uri=urn%3Arequests%3Aahy4ohgo");
        assertThat(ar.toURI().toString()).isEqualTo("https://c2id.com/login?request_uri=urn%3Arequests%3Aahy4ohgo");

        ar = AuthorizationRequest.parse(ar.toURI());

        assertThat(ar.getResponseType()).isNull();
        assertThat(ar.getClientID()).isNull();
        assertThat(ar.getRedirectionURI()).isNull();
        assertThat(ar.getScope()).isNull();
        assertThat(ar.getState()).isNull();
        assertThat(ar.getResponseMode()).isNull();
        assertThat(ar.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(ar.getResources()).isNull();
        assertThat(ar.includeGrantedScopes()).isFalse();
        assertThat(ar.getCustomParameter("custom-param")).isNull();
        assertThat(ar.getCustomParameters().isEmpty()).isTrue();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isEqualTo(requestURI);
        assertThat(ar.getRequestObject()).isNull();
        assertThat(ar.specifiesRequestObject()).isTrue();
    }

    @Test
    public void testBuilder_requestURI_coreTopLevelParams() {

        URI requestURI = URI.create("urn:requests:ahy4ohgo");
        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");

        AuthorizationRequest ar = new AuthorizationRequest.Builder(requestURI)
                .responseType(rt)
                .clientID(clientID)
                .build();

        assertThat(ar.getRequestURI()).isEqualTo(requestURI);
        assertThat(ar.getResponseType()).isEqualTo(rt);
        assertThat(ar.getClientID()).isEqualTo(clientID);

        try {
            new AuthorizationRequest.Builder(requestURI).responseType(null);
            fail("Core response_type when set not null");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The response type must not be null");
        }

        try {
            new AuthorizationRequest.Builder(requestURI).clientID(null);
            fail("Core client_id when set not null");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The client ID must not be null");
        }
    }

    @Test
    public void testJAR_requestURI_requiredTopLevelParams()
            throws OAuth2JSONParseException {

        URI endpointURI = URI.create("https://c2id.com/login");
        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");
        URI requestURI = URI.create("urn:requests:ahy4ohgo");

        AuthorizationRequest ar = new AuthorizationRequest.Builder(rt, clientID)
                .requestURI(requestURI)
                .endpointURI(endpointURI)
                .build();

        assertThat(ar.getResponseType()).isEqualTo(rt);
        assertThat(ar.getClientID()).isEqualTo(clientID);
        assertThat(ar.getRedirectionURI()).isNull();
        assertThat(ar.getScope()).isNull();
        assertThat(ar.getState()).isNull();
        assertThat(ar.getResponseMode()).isNull();
        assertThat(ar.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(ar.getResources()).isNull();
        assertThat(ar.includeGrantedScopes()).isFalse();
        assertThat(ar.getCustomParameter("custom-param")).isNull();
        assertThat(ar.getCustomParameters().isEmpty()).isTrue();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isEqualTo(requestURI);
        assertThat(ar.getRequestObject()).isNull();
        assertThat(ar.specifiesRequestObject()).isTrue();

        ar = AuthorizationRequest.parse(ar.toURI());

        assertThat(ar.getResponseType()).isEqualTo(rt);
        assertThat(ar.getClientID()).isEqualTo(clientID);
        assertThat(ar.getRedirectionURI()).isNull();
        assertThat(ar.getScope()).isNull();
        assertThat(ar.getState()).isNull();
        assertThat(ar.getResponseMode()).isNull();
        assertThat(ar.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(ar.getResources()).isNull();
        assertThat(ar.includeGrantedScopes()).isFalse();
        assertThat(ar.getCustomParameter("custom-param")).isNull();
        assertThat(ar.getCustomParameters().isEmpty()).isTrue();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isEqualTo(requestURI);
        assertThat(ar.getRequestObject()).isNull();
        assertThat(ar.specifiesRequestObject()).isTrue();
    }

    @Test
    public void testJAR_requestObject_only()
            throws OAuth2JSONParseException {

        URI endpointURI = URI.create("https://c2id.com/login");
        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");

        AuthorizationRequest jar = new AuthorizationRequest.Builder(rt, clientID)
                .build();

        JWTClaimsSet jwtClaimsSet = jar.toJWTClaimsSet();

        JWT requestObject = new PlainJWT(jwtClaimsSet);

        AuthorizationRequest ar = new AuthorizationRequest.Builder(requestObject)
                .endpointURI(endpointURI)
                .build();

        assertThat(ar.getResponseType()).isNull();
        assertThat(ar.getClientID()).isNull();
        assertThat(ar.getRedirectionURI()).isNull();
        assertThat(ar.getScope()).isNull();
        assertThat(ar.getState()).isNull();
        assertThat(ar.getResponseMode()).isNull();
        assertThat(ar.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(ar.getResources()).isNull();
        assertThat(ar.includeGrantedScopes()).isFalse();
        assertThat(ar.getCustomParameter("custom-param")).isNull();
        assertThat(ar.getCustomParameters().isEmpty()).isTrue();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isNull();
        assertThat(ar.getRequestObject()).isEqualTo(requestObject);
        assertThat(ar.specifiesRequestObject()).isTrue();

        assertThat(ar.toQueryString()).isEqualTo("request=eyJhbGciOiJub25lIn0.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6IjEyMyJ9.");
        assertThat(ar.toURI().toString()).isEqualTo("https://c2id.com/login?request=eyJhbGciOiJub25lIn0.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6IjEyMyJ9.");

        ar = AuthorizationRequest.parse(ar.toURI());

        assertThat(ar.getResponseType()).isNull();
        assertThat(ar.getClientID()).isNull();
        assertThat(ar.getRedirectionURI()).isNull();
        assertThat(ar.getScope()).isNull();
        assertThat(ar.getState()).isNull();
        assertThat(ar.getResponseMode()).isNull();
        assertThat(ar.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(ar.getResources()).isNull();
        assertThat(ar.includeGrantedScopes()).isFalse();
        assertThat(ar.getCustomParameter("custom-param")).isNull();
        assertThat(ar.getCustomParameters().isEmpty()).isTrue();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isNull();
        assertThat(ar.getRequestObject().serialize()).isEqualTo(requestObject.serialize());
        assertThat(ar.specifiesRequestObject()).isTrue();
    }

    @Test
    public void testJAR_requestObject_requiredTopLevelParams()
            throws OAuth2JSONParseException {

        URI endpointURI = URI.create("https://c2id.com/login");
        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");

        AuthorizationRequest jar = new AuthorizationRequest.Builder(rt, clientID)
                .build();

        JWTClaimsSet jwtClaimsSet = jar.toJWTClaimsSet();

        JWT requestObject = new PlainJWT(jwtClaimsSet);

        AuthorizationRequest ar = new AuthorizationRequest.Builder(rt, clientID)
                .requestObject(requestObject)
                .endpointURI(endpointURI)
                .build();

        assertThat(ar.getResponseType()).isEqualTo(rt);
        assertThat(ar.getClientID()).isEqualTo(clientID);
        assertThat(ar.getRedirectionURI()).isNull();
        assertThat(ar.getScope()).isNull();
        assertThat(ar.getState()).isNull();
        assertThat(ar.getResponseMode()).isNull();
        assertThat(ar.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(ar.getResources()).isNull();
        assertThat(ar.includeGrantedScopes()).isFalse();
        assertThat(ar.getCustomParameter("custom-param")).isNull();
        assertThat(ar.getCustomParameters().isEmpty()).isTrue();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isNull();
        assertThat(ar.getRequestObject()).isEqualTo(requestObject);
        assertThat(ar.specifiesRequestObject()).isTrue();

        ar = AuthorizationRequest.parse(ar.toURI());

        assertThat(ar.getResponseType()).isEqualTo(rt);
        assertThat(ar.getClientID()).isEqualTo(clientID);
        assertThat(ar.getRedirectionURI()).isNull();
        assertThat(ar.getScope()).isNull();
        assertThat(ar.getState()).isNull();
        assertThat(ar.getResponseMode()).isNull();
        assertThat(ar.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(ar.getResources()).isNull();
        assertThat(ar.includeGrantedScopes()).isFalse();
        assertThat(ar.getCustomParameter("custom-param")).isNull();
        assertThat(ar.getCustomParameters().isEmpty()).isTrue();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isNull();
        assertThat(ar.getRequestObject().serialize()).isEqualTo(requestObject.serialize());
        assertThat(ar.specifiesRequestObject()).isTrue();
    }

    @Test
    public void testBuilder_nullRequestObject() {

        try {
            new AuthorizationRequest.Builder((JWT) null);
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The request object must not be null");
        }
    }

    @Test
    public void testBuilder_nullRequestURI() {

        try {
            new AuthorizationRequest.Builder((URI) null);
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The request URI must not be null");
        }
    }

    @Test
    public void testBuilder_copyConstructor_requestObject() {

        URI endpointURI = URI.create("https://c2id.com/login");
        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");

        AuthorizationRequest jar = new AuthorizationRequest.Builder(rt, clientID)
                .build();

        JWTClaimsSet jwtClaimsSet = jar.toJWTClaimsSet();

        JWT requestObject = new PlainJWT(jwtClaimsSet);

        AuthorizationRequest ar = new AuthorizationRequest.Builder(requestObject)
                .endpointURI(endpointURI)
                .build();

        ar = new AuthorizationRequest.Builder(ar)
                .build();

        assertThat(ar.getResponseType()).isNull();
        assertThat(ar.getClientID()).isNull();
        assertThat(ar.getRedirectionURI()).isNull();
        assertThat(ar.getScope()).isNull();
        assertThat(ar.getState()).isNull();
        assertThat(ar.getResponseMode()).isNull();
        assertThat(ar.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(ar.getResources()).isNull();
        assertThat(ar.includeGrantedScopes()).isFalse();
        assertThat(ar.getCustomParameter("custom-param")).isNull();
        assertThat(ar.getCustomParameters().isEmpty()).isTrue();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isNull();
        assertThat(ar.getRequestObject()).isEqualTo(requestObject);
        assertThat(ar.specifiesRequestObject()).isTrue();
    }

    @Test
    public void testBuilder_copyConstructor_requestURI() {

        URI endpointURI = URI.create("https://c2id.com/login");
        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");
        URI requestURI = URI.create("urn:requests:ahy4ohgo");

        AuthorizationRequest ar = new AuthorizationRequest.Builder(rt, clientID)
                .requestURI(requestURI)
                .endpointURI(endpointURI)
                .build();

        ar = new AuthorizationRequest.Builder(ar)
                .build();

        assertThat(ar.getResponseType()).isEqualTo(rt);
        assertThat(ar.getClientID()).isEqualTo(clientID);
        assertThat(ar.getRedirectionURI()).isNull();
        assertThat(ar.getScope()).isNull();
        assertThat(ar.getState()).isNull();
        assertThat(ar.getResponseMode()).isNull();
        assertThat(ar.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(ar.getResources()).isNull();
        assertThat(ar.includeGrantedScopes()).isFalse();
        assertThat(ar.getCustomParameter("custom-param")).isNull();
        assertThat(ar.getCustomParameters().isEmpty()).isTrue();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isEqualTo(requestURI);
        assertThat(ar.getRequestObject()).isNull();
        assertThat(ar.specifiesRequestObject()).isTrue();
    }

    @Test
    public void testBuilder_reject_requestObjectWithRequestURI() {

        URI endpointURI = URI.create("https://c2id.com/login");
        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");

        AuthorizationRequest jar = new AuthorizationRequest.Builder(rt, clientID)
                .build();

        JWTClaimsSet jwtClaimsSet = jar.toJWTClaimsSet();

        JWT requestObject = new PlainJWT(jwtClaimsSet);

        try {
            new AuthorizationRequest.Builder(requestObject)
                    .endpointURI(endpointURI)
                    .requestURI(URI.create("urn:requests:uogo3ora"))
                    .build();
            fail();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo("Either a request object or a request URI must be specified, but not both");
            assertThat(e.getCause()).isInstanceOf(IllegalArgumentException.class);
            assertThat(e.getCause().getMessage()).isEqualTo("Either a request object or a request URI must be specified, but not both");
        }
    }

    @Test
    public void test_toJWTClaimsSet_rejectIfNestedRequestObject() {

        URI endpointURI = URI.create("https://c2id.com/login");
        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");

        AuthorizationRequest jar = new AuthorizationRequest.Builder(rt, clientID)
                .build();

        JWTClaimsSet jwtClaimsSet = jar.toJWTClaimsSet();

        JWT requestObject = new PlainJWT(jwtClaimsSet);

        AuthorizationRequest ar = new AuthorizationRequest.Builder(requestObject)
                .endpointURI(endpointURI)
                .build();

        try {
            ar.toJWTClaimsSet();
            fail();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo("Cannot create nested JWT secured authorization request");
        }
    }

    @Test
    public void test_toJWTClaimsSet_rejectIfNestedRequestURI() {

        URI endpointURI = URI.create("https://c2id.com/login");
        URI requestURI = URI.create("urn:requests:uogo3ora");

        AuthorizationRequest ar = new AuthorizationRequest.Builder(requestURI)
                .endpointURI(endpointURI)
                .build();

        try {
            ar.toJWTClaimsSet();
            fail();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo("Cannot create nested JWT secured authorization request");
        }
    }

    @Test
    public void testParseInvalidRequestURI() {

        try {
            AuthorizationRequest.parse(URI.create("https://c2id.com/login?request_uri=%3A"));
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Invalid \"request_uri\" parameter: Expected scheme name at index 0: :");
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
        }
    }

    @Test
    public void testParseInvalidRequestObject() {

        try {
            AuthorizationRequest.parse(URI.create("https://c2id.com/login?request=abc"));
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Invalid \"request_object\" parameter: Invalid JWT serialization: Missing dot delimiter(s)");
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
        }
    }

    @Test
    public void testParseInvalidRequestURI_redirectionInfo() {

        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");
        URI redirectionURI = URI.create("https://example.com/cb");
        State state = new State();

        Map<String, List<String>> params = new AuthorizationRequest.Builder(rt, clientID)
                .redirectionURI(redirectionURI)
                .state(state)
                .build()
                .toParameters();
        params.put("request_uri", Collections.singletonList(":"));

        try {
            AuthorizationRequest.parse(params);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Invalid \"request_uri\" parameter: Expected scheme name at index 0: :");
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Invalid \"request_uri\" parameter: Expected scheme name at index 0: :");
            assertThat(e.getClientID()).isEqualTo(clientID);
            assertThat(e.getRedirectionURI()).isEqualTo(redirectionURI);
            assertThat(e.getState()).isEqualTo(state);
        }
    }

    @Test
    public void testParseInvalidRequestObject_redirectionInfo() {

        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");
        URI redirectionURI = URI.create("https://example.com/cb");
        State state = new State();

        Map<String, List<String>> params = new AuthorizationRequest.Builder(rt, clientID)
                .redirectionURI(redirectionURI)
                .state(state)
                .build()
                .toParameters();
        params.put("request", Collections.singletonList("abc"));

        try {
            AuthorizationRequest.parse(params);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Invalid \"request_object\" parameter: Invalid JWT serialization: Missing dot delimiter(s)");
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Invalid \"request_object\" parameter: Invalid JWT serialization: Missing dot delimiter(s)");
            assertThat(e.getClientID()).isEqualTo(clientID);
            assertThat(e.getRedirectionURI()).isEqualTo(redirectionURI);
            assertThat(e.getState()).isEqualTo(state);
        }
    }

    @Test
    public void testParse_missingResponseType() {

        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");
        URI redirectionURI = URI.create("https://example.com/cb");
        State state = new State();

        Map<String, List<String>> params = new AuthorizationRequest.Builder(rt, clientID)
                .redirectionURI(redirectionURI)
                .state(state)
                .build()
                .toParameters();
        params.remove("response_type");

        try {
            AuthorizationRequest.parse(params);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing \"response_type\" parameter");
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"response_type\" parameter");
            assertThat(e.getClientID()).isEqualTo(clientID);
            assertThat(e.getRedirectionURI()).isEqualTo(redirectionURI);
            assertThat(e.getResponseMode()).isEqualTo(ResponseMode.QUERY);
            assertThat(e.getState()).isEqualTo(e.getState());
        }
    }

    @Test
    public void testParse_missingClientID() {

        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");

        Map<String, List<String>> params = new AuthorizationRequest.Builder(rt, clientID)
                .build()
                .toParameters();
        params.remove("client_id");

        try {
            AuthorizationRequest.parse(params);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing \"client_id\" parameter");
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"client_id\" parameter");
            assertThat(e.getClientID()).isNull();
            assertThat(e.getRedirectionURI()).isNull();
            assertThat(e.getResponseMode()).isNull();
            assertThat(e.getState()).isNull();
        }
    }

    @Test
    public void testParse_missingClientID_redirectionInfoIgnored() {

        ResponseType rt = new ResponseType("code");
        ClientID clientID = new ClientID("123");
        URI redirectionURI = URI.create("https://example.com/cb");
        State state = new State();

        Map<String, List<String>> params = new AuthorizationRequest.Builder(rt, clientID)
                .redirectionURI(redirectionURI)
                .state(state)
                .build()
                .toParameters();
        params.remove("client_id");

        try {
            AuthorizationRequest.parse(params);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing \"client_id\" parameter");
            assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"client_id\" parameter");
            assertThat(e.getClientID()).isNull();
            assertThat(e.getRedirectionURI()).isNull();
            assertThat(e.getResponseMode()).isNull();
            assertThat(e.getState()).isNull();
        }
    }
}
