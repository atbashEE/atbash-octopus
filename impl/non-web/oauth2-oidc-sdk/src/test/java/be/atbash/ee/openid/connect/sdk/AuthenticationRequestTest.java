/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.*;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.pkce.CodeChallenge;
import be.atbash.ee.oauth2.sdk.pkce.CodeChallengeMethod;
import be.atbash.ee.oauth2.sdk.pkce.CodeVerifier;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.openid.connect.sdk.claims.ACR;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.ListKeyManager;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SelectorCriteria;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.*;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.Test;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class AuthenticationRequestTest {


    private final static String EXAMPLE_JWT_STRING =
            "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
                    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
                    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
                    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @Test
    public void testRegisteredParameters() {

        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("response_type")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("response_mode")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("client_id")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("redirect_uri")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("scope")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("state")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("code_challenge")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("code_challenge_method")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("resource")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("include_granted_scopes")).isTrue();

        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("nonce")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("display")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("prompt")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("max_age")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("ui_locales")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("claims_locales")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("id_token_hint")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("login_hint")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("acr_values")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("claims")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("request_uri")).isTrue();
        assertThat(AuthenticationRequest.getRegisteredParameterNames().contains("request")).isTrue();

        assertThat(AuthenticationRequest.getRegisteredParameterNames()).hasSize(22);
    }

    @Test
    public void testMinimalConstructor()
            throws Exception {

        URI uri = new URI("https://c2id.com/login/");

        ResponseType rts = new ResponseType();
        rts.add(ResponseType.Value.CODE);

        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        scope.add(OIDCScopeValue.PROFILE);

        ClientID clientID = new ClientID("123456789");

        URI redirectURI = new URI("http://www.deezer.com/en/");

        State state = new State("abc");
        Nonce nonce = new Nonce("xyz");

        AuthenticationRequest request =
                new AuthenticationRequest(uri, rts, scope, clientID, redirectURI, state, nonce);

        assertThat(request.getEndpointURI()).isEqualTo(uri);

        ResponseType rtsOut = request.getResponseType();
        assertThat(rtsOut.contains(ResponseType.Value.CODE)).isTrue();
        assertThat(rtsOut).hasSize(1);

        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);

        Scope scopeOut = request.getScope();
        assertThat(scopeOut.contains(OIDCScopeValue.OPENID)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.EMAIL)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.PROFILE)).isTrue();
        assertThat(scopeOut).hasSize(3);

        assertThat(request.getClientID()).isEqualTo(new ClientID("123456789"));

        assertThat(request.getRedirectionURI()).isEqualTo(new URI("http://www.deezer.com/en/"));

        assertThat(request.getState()).isEqualTo(new State("abc"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("xyz"));

        assertThat(request.getResponseMode()).isNull();
        assertThat(request.getDisplay()).isNull();
        assertThat(request.getPrompt()).isNull();
        assertThat(request.getMaxAge()).isEqualTo(-1);
        assertThat(request.getIDTokenHint()).isNull();
        assertThat(request.getLoginHint()).isNull();
        assertThat(request.getACRValues()).isNull();
        assertThat(request.getClaims()).isNull();
        assertThat(request.getRequestObject()).isNull();
        assertThat(request.getRequestURI()).isNull();
        assertThat(request.getCodeChallenge()).isNull();
        assertThat(request.getCodeChallengeMethod()).isNull();
        assertThat(request.getResources()).isNull();
        assertThat(request.includeGrantedScopes()).isFalse();
        assertThat(request.getCustomParameters().isEmpty()).isTrue();

        // Check the resulting query string
        String queryString = request.toQueryString();

        request = AuthenticationRequest.parse(uri, queryString);

        assertThat(request.getEndpointURI()).isEqualTo(uri);

        rtsOut = request.getResponseType();
        assertThat(rtsOut.contains(ResponseType.Value.CODE)).isTrue();
        assertThat(rtsOut).hasSize(1);

        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);

        scopeOut = request.getScope();
        assertThat(scopeOut.contains(OIDCScopeValue.OPENID)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.EMAIL)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.PROFILE)).isTrue();
        assertThat(scopeOut).hasSize(3);

        assertThat(request.getClientID()).isEqualTo(new ClientID("123456789"));

        assertThat(request.getRedirectionURI()).isEqualTo(new URI("http://www.deezer.com/en/"));

        assertThat(request.getState()).isEqualTo(new State("abc"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("xyz"));

        assertThat(request.getResponseMode()).isNull();
        assertThat(request.getDisplay()).isNull();
        assertThat(request.getPrompt()).isNull();
        assertThat(request.getMaxAge()).isEqualTo(-1);
        assertThat(request.getIDTokenHint()).isNull();
        assertThat(request.getLoginHint()).isNull();
        assertThat(request.getACRValues()).isNull();
        assertThat(request.getClaims()).isNull();
        assertThat(request.getRequestObject()).isNull();
        assertThat(request.getRequestURI()).isNull();
        assertThat(request.getCodeChallenge()).isNull();
        assertThat(request.getCodeChallengeMethod()).isNull();
        assertThat(request.getResources()).isNull();
        assertThat(request.includeGrantedScopes()).isFalse();
        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testAltParse()
            throws Exception {

        URI uri = new URI("https://c2id.com/login/");

        ResponseType rts = new ResponseType();
        rts.add(ResponseType.Value.CODE);

        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        scope.add(OIDCScopeValue.PROFILE);

        ClientID clientID = new ClientID("123456789");

        URI redirectURI = new URI("http://www.deezer.com/en/");

        State state = new State("abc");
        Nonce nonce = new Nonce("xyz");

        AuthenticationRequest request =
                new AuthenticationRequest(uri, rts, scope, clientID, redirectURI, state, nonce);

        // Check the resulting query string
        String queryString = request.toQueryString();

        request = AuthenticationRequest.parse(queryString);

        assertThat(request.getEndpointURI()).isNull();

        ResponseType rtsOut = request.getResponseType();
        assertThat(rtsOut.contains(ResponseType.Value.CODE)).isTrue();
        assertThat(rtsOut).hasSize(1);

        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);

        Scope scopeOut = request.getScope();
        assertThat(scopeOut.contains(OIDCScopeValue.OPENID)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.EMAIL)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.PROFILE)).isTrue();
        assertThat(scopeOut).hasSize(3);

        assertThat(request.getClientID()).isEqualTo(new ClientID("123456789"));

        assertThat(request.getRedirectionURI()).isEqualTo(new URI("http://www.deezer.com/en/"));

        assertThat(request.getState()).isEqualTo(new State("abc"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("xyz"));

        assertThat(request.getMaxAge()).isEqualTo(-1);

        assertThat(request.getCodeChallenge()).isNull();
        assertThat(request.getCodeChallengeMethod()).isNull();

        assertThat(request.getResources()).isNull();

        assertThat(request.includeGrantedScopes()).isFalse();

        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testExtendedConstructor_withCustomParams()
            throws Exception {

        URI uri = new URI("https://c2id.com/login/");

        ResponseType rts = new ResponseType();
        rts.add(ResponseType.Value.CODE);

        ResponseMode rm = ResponseMode.FORM_POST;

        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        scope.add(OIDCScopeValue.PROFILE);

        ClientID clientID = new ClientID("123456789");

        URI redirectURI = new URI("http://www.deezer.com/en/");

        State state = new State("abc");
        Nonce nonce = new Nonce("xyz");

        // Extended parameters
        Display display = Display.POPUP;

        Prompt prompt = new Prompt();
        prompt.add(Prompt.Type.LOGIN);
        prompt.add(Prompt.Type.CONSENT);

        int maxAge = 3600;

        JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

        String loginHint = "alice123";

        List<ACR> acrValues = new LinkedList<>();
        acrValues.add(new ACR("1"));
        acrValues.add(new ACR("2"));

        ClaimsRequest claims = new ClaimsRequest();
        claims.addUserInfoClaim("given_name");
        claims.addUserInfoClaim("family_name");

        CodeVerifier codeVerifier = new CodeVerifier();
        CodeChallengeMethod codeChallengeMethod = CodeChallengeMethod.S256;
        CodeChallenge codeChallenge = CodeChallenge.compute(codeChallengeMethod, codeVerifier);

        List<URI> resources = Collections.singletonList(URI.create("https://rs1.com"));

        Map<String, List<String>> customParams = new HashMap<>();
        customParams.put("x", Collections.singletonList("100"));
        customParams.put("y", Collections.singletonList("200"));
        customParams.put("z", Collections.singletonList("300"));

        AuthenticationRequest request = new AuthenticationRequest(
                uri, rts, rm, scope, clientID, redirectURI, state, nonce,
                display, prompt, maxAge,
                idTokenHint, loginHint, acrValues, claims, null, null,
                codeChallenge, codeChallengeMethod,
                resources,
                true,
                customParams);

        assertThat(request.getEndpointURI()).isEqualTo(uri);

        ResponseType rtsOut = request.getResponseType();
        assertThat(rtsOut.contains(ResponseType.Value.CODE)).isTrue();
        assertThat(rtsOut).hasSize(1);

        Scope scopeOut = request.getScope();
        assertThat(scopeOut.contains(OIDCScopeValue.OPENID)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.EMAIL)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.PROFILE)).isTrue();
        assertThat(scopeOut).hasSize(3);

        assertThat(request.getClientID()).isEqualTo(new ClientID("123456789"));

        assertThat(request.getRedirectionURI()).isEqualTo(new URI("http://www.deezer.com/en/"));

        assertThat(request.getState()).isEqualTo(new State("abc"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("xyz"));

        // Check extended parameters

        assertThat(request.getResponseMode()).isEqualTo(rm);
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FORM_POST);

        assertThat(request.getDisplay()).isEqualTo(Display.POPUP);

        Prompt promptOut = request.getPrompt();
        assertThat(promptOut.contains(Prompt.Type.LOGIN)).isTrue();
        assertThat(promptOut.contains(Prompt.Type.CONSENT)).isTrue();
        assertThat(promptOut.size()).isEqualTo(2);

        assertThat(request.getMaxAge()).isEqualTo(3600);

        assertThat(request.getIDTokenHint().getParsedString()).isEqualTo(EXAMPLE_JWT_STRING);

        assertThat(request.getLoginHint()).isEqualTo(loginHint);

        List<ACR> acrValuesOut = request.getACRValues();
        assertThat(acrValuesOut.get(0).toString()).isEqualTo("1");
        assertThat(acrValuesOut.get(1).toString()).isEqualTo("2");
        assertThat(acrValuesOut).hasSize(2);

        ClaimsRequest claimsOut = request.getClaims();

        assertThat(claimsOut.getUserInfoClaims()).hasSize(2);

        assertThat(request.getCodeChallenge()).isEqualTo(codeChallenge);
        assertThat(request.getCodeChallengeMethod()).isEqualTo(codeChallengeMethod);

        assertThat(request.getResources()).isEqualTo(resources);

        assertThat(request.getCustomParameter("x")).isEqualTo(Collections.singletonList("100"));
        assertThat(request.getCustomParameter("y")).isEqualTo(Collections.singletonList("200"));
        assertThat(request.getCustomParameter("z")).isEqualTo(Collections.singletonList("300"));
        assertThat(request.getCustomParameters()).hasSize(3);

        // Check the resulting query string
        String queryString = request.toQueryString();

        request = AuthenticationRequest.parse(uri, queryString);

        assertThat(request.getEndpointURI()).isEqualTo(uri);

        rtsOut = request.getResponseType();
        assertThat(rtsOut.contains(ResponseType.Value.CODE)).isTrue();
        assertThat(rtsOut).hasSize(1);

        scopeOut = request.getScope();
        assertThat(scopeOut.contains(OIDCScopeValue.OPENID)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.EMAIL)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.PROFILE)).isTrue();
        assertThat(scopeOut).hasSize(3);

        assertThat(request.getClientID()).isEqualTo(new ClientID("123456789"));

        assertThat(request.getRedirectionURI()).isEqualTo(new URI("http://www.deezer.com/en/"));

        assertThat(request.getState()).isEqualTo(new State("abc"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("xyz"));

        // Check extended parameters

        assertThat(request.getResponseMode()).isEqualTo(rm);
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FORM_POST);

        assertThat(request.getDisplay()).isEqualTo(Display.POPUP);

        promptOut = request.getPrompt();
        assertThat(promptOut.contains(Prompt.Type.LOGIN)).isTrue();
        assertThat(promptOut.contains(Prompt.Type.CONSENT)).isTrue();
        assertThat(promptOut.size()).isEqualTo(2);

        assertThat(request.getMaxAge()).isEqualTo(3600);


        assertThat(request.getIDTokenHint().getParsedString()).isEqualTo(EXAMPLE_JWT_STRING);

        assertThat(request.getLoginHint()).isEqualTo(loginHint);

        acrValuesOut = request.getACRValues();
        assertThat(acrValuesOut.get(0).toString()).isEqualTo("1");
        assertThat(acrValuesOut.get(1).toString()).isEqualTo("2");
        assertThat(acrValuesOut).hasSize(2);

        claimsOut = request.getClaims();

        assertThat(claimsOut.getUserInfoClaims()).hasSize(2);

        assertThat(request.getCodeChallenge()).isEqualTo(codeChallenge);
        assertThat(request.getCodeChallengeMethod()).isEqualTo(codeChallengeMethod);

        assertThat(request.getResources()).isEqualTo(resources);

        assertThat(request.includeGrantedScopes()).isTrue();

        assertThat(request.getCustomParameter("x")).isEqualTo(Collections.singletonList("100"));
        assertThat(request.getCustomParameter("y")).isEqualTo(Collections.singletonList("200"));
        assertThat(request.getCustomParameter("z")).isEqualTo(Collections.singletonList("300"));
        assertThat(request.getCustomParameters()).hasSize(3);
    }

    @Test
    public void testRequestObjectConstructor()
            throws Exception {

        URI uri = new URI("https://c2id.com/login");

        ResponseType rts = new ResponseType();
        rts.add(ResponseType.Value.CODE);

        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        scope.add(OIDCScopeValue.PROFILE);

        ClientID clientID = new ClientID("123456789");

        URI redirectURI = new URI("http://www.deezer.com/en/");

        State state = new State("abc");
        Nonce nonce = new Nonce("xyz");

        // Extended parameters
        Display display = Display.POPUP;

        Prompt prompt = new Prompt();
        prompt.add(Prompt.Type.LOGIN);
        prompt.add(Prompt.Type.CONSENT);

        int maxAge = 3600;

        JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

        String loginHint = "alice123";

        List<ACR> acrValues = new LinkedList<>();
        acrValues.add(new ACR("1"));
        acrValues.add(new ACR("2"));

        ClaimsRequest claims = new ClaimsRequest();
        claims.addUserInfoClaim("given_name");
        claims.addUserInfoClaim("family_name");

        JWT requestObject = JWTParser.parse(EXAMPLE_JWT_STRING);

        AuthenticationRequest request = new AuthenticationRequest(
                uri, rts, null, scope, clientID, redirectURI, state, nonce,
                display, prompt, maxAge,
                idTokenHint, loginHint, acrValues, claims, requestObject, null,
                null, null, null, false, null);

        assertThat(request.getEndpointURI()).isEqualTo(uri);

        ResponseType rtsOut = request.getResponseType();
        assertThat(rtsOut.contains(ResponseType.Value.CODE)).isTrue();
        assertThat(rtsOut).hasSize(1);

        Scope scopeOut = request.getScope();
        assertThat(scopeOut.contains(OIDCScopeValue.OPENID)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.EMAIL)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.PROFILE)).isTrue();
        assertThat(scopeOut).hasSize(3);

        assertThat(request.getClientID()).isEqualTo(new ClientID("123456789"));

        assertThat(request.getRedirectionURI()).isEqualTo(new URI("http://www.deezer.com/en/"));

        assertThat(request.getState()).isEqualTo(new State("abc"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("xyz"));

        // Check extended parameters

        assertThat(request.getResponseMode()).isNull();

        assertThat(request.getDisplay()).isEqualTo(Display.POPUP);

        Prompt promptOut = request.getPrompt();
        assertThat(promptOut.contains(Prompt.Type.LOGIN)).isTrue();
        assertThat(promptOut.contains(Prompt.Type.CONSENT)).isTrue();
        assertThat(promptOut.size()).isEqualTo(2);

        assertThat(request.getMaxAge()).isEqualTo(3600);

        assertThat(request.getIDTokenHint().getParsedString()).isEqualTo(EXAMPLE_JWT_STRING);

        assertThat(request.getLoginHint()).isEqualTo(loginHint);

        List<ACR> acrValuesOut = request.getACRValues();
        assertThat(acrValuesOut.get(0).toString()).isEqualTo("1");
        assertThat(acrValuesOut.get(1).toString()).isEqualTo("2");
        assertThat(acrValuesOut).hasSize(2);

        ClaimsRequest claimsOut = request.getClaims();

        assertThat(claimsOut.getUserInfoClaims()).hasSize(2);

        assertThat(request.getRequestObject().getParsedString()).isEqualTo(EXAMPLE_JWT_STRING);


        // Check the resulting query string
        String queryString = request.toQueryString();


        request = AuthenticationRequest.parse(uri, queryString);

        assertThat(request.getEndpointURI()).isEqualTo(uri);

        rtsOut = request.getResponseType();
        assertThat(rtsOut.contains(ResponseType.Value.CODE)).isTrue();
        assertThat(rtsOut).hasSize(1);

        scopeOut = request.getScope();
        assertThat(scopeOut.contains(OIDCScopeValue.OPENID)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.EMAIL)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.PROFILE)).isTrue();
        assertThat(scopeOut).hasSize(3);

        assertThat(request.getClientID()).isEqualTo(new ClientID("123456789"));

        assertThat(request.getRedirectionURI()).isEqualTo(new URI("http://www.deezer.com/en/"));

        assertThat(request.getState()).isEqualTo(new State("abc"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("xyz"));

        // Check extended parameters

        assertThat(request.getResponseMode()).isNull();

        assertThat(request.getDisplay()).isEqualTo(Display.POPUP);

        promptOut = request.getPrompt();
        assertThat(promptOut.contains(Prompt.Type.LOGIN)).isTrue();
        assertThat(promptOut.contains(Prompt.Type.CONSENT)).isTrue();
        assertThat(promptOut.size()).isEqualTo(2);

        assertThat(request.getMaxAge()).isEqualTo(3600);


        assertThat(request.getIDTokenHint().getParsedString()).isEqualTo(EXAMPLE_JWT_STRING);

        assertThat(request.getLoginHint()).isEqualTo(loginHint);

        acrValuesOut = request.getACRValues();
        assertThat(acrValuesOut.get(0).toString()).isEqualTo("1");
        assertThat(acrValuesOut.get(1).toString()).isEqualTo("2");
        assertThat(acrValuesOut).hasSize(2);

        claimsOut = request.getClaims();

        assertThat(claimsOut.getUserInfoClaims()).hasSize(2);

        assertThat(request.getRequestObject().getParsedString()).isEqualTo(EXAMPLE_JWT_STRING);
    }

    @Test
    public void testRequestURIConstructor()
            throws Exception {

        URI uri = new URI("https://c2id.com/login/");

        ResponseType rts = new ResponseType();
        rts.add(ResponseType.Value.CODE);

        Scope scope = new Scope();
        scope.add(OIDCScopeValue.OPENID);
        scope.add(OIDCScopeValue.EMAIL);
        scope.add(OIDCScopeValue.PROFILE);

        ClientID clientID = new ClientID("123456789");

        URI redirectURI = new URI("http://www.deezer.com/en/");

        State state = new State("abc");
        Nonce nonce = new Nonce("xyz");

        // Extended parameters
        Display display = Display.POPUP;

        Prompt prompt = new Prompt();
        prompt.add(Prompt.Type.LOGIN);
        prompt.add(Prompt.Type.CONSENT);

        int maxAge = 3600;

        JWT idTokenHint = JWTParser.parse(EXAMPLE_JWT_STRING);

        String loginHint = "alice123";

        List<ACR> acrValues = new LinkedList<>();
        acrValues.add(new ACR("1"));
        acrValues.add(new ACR("2"));

        ClaimsRequest claims = new ClaimsRequest();
        claims.addUserInfoClaim("given_name");
        claims.addUserInfoClaim("family_name");

        URI requestURI = new URI("http://example.com/request-object.jwt#1234");

        AuthenticationRequest request = new AuthenticationRequest(
                uri, rts, null, scope, clientID, redirectURI, state, nonce,
                display, prompt, maxAge,
                idTokenHint, loginHint, acrValues, claims, null, requestURI,
                null, null, null, false, null);

        assertThat(request.getEndpointURI()).isEqualTo(uri);

        ResponseType rtsOut = request.getResponseType();
        assertThat(rtsOut.contains(ResponseType.Value.CODE)).isTrue();
        assertThat(rtsOut).hasSize(1);

        Scope scopeOut = request.getScope();
        assertThat(scopeOut.contains(OIDCScopeValue.OPENID)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.EMAIL)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.PROFILE)).isTrue();
        assertThat(scopeOut).hasSize(3);

        assertThat(request.getClientID()).isEqualTo(new ClientID("123456789"));

        assertThat(request.getRedirectionURI()).isEqualTo(new URI("http://www.deezer.com/en/"));

        assertThat(request.getState()).isEqualTo(new State("abc"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("xyz"));

        // Check extended parameters

        assertThat(request.getResponseMode()).isNull();

        assertThat(request.getDisplay()).isEqualTo(Display.POPUP);

        Prompt promptOut = request.getPrompt();
        assertThat(promptOut.contains(Prompt.Type.LOGIN)).isTrue();
        assertThat(promptOut.contains(Prompt.Type.CONSENT)).isTrue();
        assertThat(promptOut.size()).isEqualTo(2);

        assertThat(request.getMaxAge()).isEqualTo(3600);

        assertThat(request.getIDTokenHint().getParsedString()).isEqualTo(EXAMPLE_JWT_STRING);

        assertThat(request.getLoginHint()).isEqualTo(loginHint);

        List<ACR> acrValuesOut = request.getACRValues();
        assertThat(acrValuesOut.get(0).toString()).isEqualTo("1");
        assertThat(acrValuesOut.get(1).toString()).isEqualTo("2");
        assertThat(acrValuesOut).hasSize(2);

        ClaimsRequest claimsOut = request.getClaims();

        assertThat(claimsOut.getUserInfoClaims()).hasSize(2);

        assertThat(request.getRequestURI()).isEqualTo(requestURI);


        // Check the resulting query string
        String queryString = request.toQueryString();


        request = AuthenticationRequest.parse(uri, queryString);

        assertThat(request.getEndpointURI()).isEqualTo(uri);

        rtsOut = request.getResponseType();
        assertThat(rtsOut.contains(ResponseType.Value.CODE)).isTrue();
        assertThat(rtsOut).hasSize(1);

        scopeOut = request.getScope();
        assertThat(scopeOut.contains(OIDCScopeValue.OPENID)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.EMAIL)).isTrue();
        assertThat(scopeOut.contains(OIDCScopeValue.PROFILE)).isTrue();
        assertThat(scopeOut).hasSize(3);

        assertThat(request.getClientID()).isEqualTo(new ClientID("123456789"));

        assertThat(request.getRedirectionURI()).isEqualTo(new URI("http://www.deezer.com/en/"));

        assertThat(request.getState()).isEqualTo(new State("abc"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("xyz"));

        // Check extended parameters

        assertThat(request.getResponseMode()).isNull();

        assertThat(request.getDisplay()).isEqualTo(Display.POPUP);

        promptOut = request.getPrompt();
        assertThat(promptOut.contains(Prompt.Type.LOGIN)).isTrue();
        assertThat(promptOut.contains(Prompt.Type.CONSENT)).isTrue();
        assertThat(promptOut.size()).isEqualTo(2);

        assertThat(request.getMaxAge()).isEqualTo(3600);


        assertThat(request.getIDTokenHint().getParsedString()).isEqualTo(EXAMPLE_JWT_STRING);

        assertThat(request.getLoginHint()).isEqualTo(loginHint);

        acrValuesOut = request.getACRValues();
        assertThat(acrValuesOut.get(0).toString()).isEqualTo("1");
        assertThat(acrValuesOut.get(1).toString()).isEqualTo("2");
        assertThat(acrValuesOut).hasSize(2);

        claimsOut = request.getClaims();

        assertThat(claimsOut.getUserInfoClaims()).hasSize(2);

        assertThat(request.getRequestURI()).isEqualTo(requestURI);
    }

    @Test
    public void testBuilderMinimal()
            throws Exception {

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid", "email"),
                new ClientID("123"),
                new URI("https://client.com/cb")).build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(request.getScope()).isEqualTo(new Scope("openid", "email"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getRedirectionURI()).isEqualTo(new URI("https://client.com/cb"));
        assertThat(request.getState()).isNull();
        assertThat(request.getNonce()).isNull();
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(request.getDisplay()).isNull();
        assertThat(request.getPrompt()).isNull();
        assertThat(request.getMaxAge()).isEqualTo(-1);
        assertThat(request.getIDTokenHint()).isNull();
        assertThat(request.getLoginHint()).isNull();
        assertThat(request.getACRValues()).isNull();
        assertThat(request.getClaims()).isNull();
        assertThat(request.getRequestObject()).isNull();
        assertThat(request.getRequestURI()).isNull();
        assertThat(request.getCodeChallenge()).isNull();
        assertThat(request.getCodeChallengeMethod()).isNull();
        assertThat(request.getResources()).isNull();
        assertThat(request.includeGrantedScopes()).isFalse();
        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testBuilderFull()
            throws Exception {

        List<ACR> acrValues = new LinkedList<>();
        acrValues.add(new ACR("1"));
        acrValues.add(new ACR("2"));

        ClaimsRequest claims = new ClaimsRequest();
        claims.addUserInfoClaim("given_name");
        claims.addUserInfoClaim("family_name");

        CodeVerifier codeVerifier = new CodeVerifier();

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType("code", "id_token"),
                new Scope("openid", "email"),
                new ClientID("123"),
                new URI("https://client.com/cb"))
                .state(new State("abc"))
                .nonce(new Nonce("def"))
                .display(Display.POPUP)
                .prompt(new Prompt(Prompt.Type.NONE))
                .maxAge(3600)
                .idTokenHint(JWTParser.parse(EXAMPLE_JWT_STRING))
                .loginHint("alice@wonderland.net")
                .acrValues(acrValues)
                .claims(claims)
                .responseMode(ResponseMode.FORM_POST)
                .codeChallenge(codeVerifier, CodeChallengeMethod.S256)
                .resources(URI.create("https://rs1.com"))
                .includeGrantedScopes(true)
                .customParameter("x", "100")
                .customParameter("y", "200")
                .customParameter("z", "300")
                .endpointURI(new URI("https://c2id.com/login"))
                .build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code", "id_token"));
        assertThat(request.getResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FORM_POST);
        assertThat(request.getScope()).isEqualTo(new Scope("openid", "email"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getRedirectionURI()).isEqualTo(new URI("https://client.com/cb"));
        assertThat(request.getState()).isEqualTo(new State("abc"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("def"));
        assertThat(request.getDisplay()).isEqualTo(Display.POPUP);
        assertThat(request.getPrompt()).isEqualTo(new Prompt(Prompt.Type.NONE));
        assertThat(request.getMaxAge()).isEqualTo(3600);
        assertThat(request.getIDTokenHint().getParsedString()).isEqualTo(EXAMPLE_JWT_STRING);
        assertThat(request.getLoginHint()).isEqualTo("alice@wonderland.net");
        assertThat(request.getACRValues()).isEqualTo(acrValues);
        assertThat(request.getClaims()).isEqualTo(claims);
        assertThat(request.getCodeChallenge()).isEqualTo(CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier));
        assertThat(request.getCodeChallengeMethod()).isEqualTo(CodeChallengeMethod.S256);
        assertThat(request.getResources()).isEqualTo(Collections.singletonList(URI.create("https://rs1.com")));
        assertThat(request.includeGrantedScopes()).isTrue();
        assertThat(request.getCustomParameter("x")).isEqualTo(Collections.singletonList("100"));
        assertThat(request.getCustomParameter("y")).isEqualTo(Collections.singletonList("200"));
        assertThat(request.getCustomParameter("z")).isEqualTo(Collections.singletonList("300"));
        assertThat(request.getCustomParameters()).hasSize(3);
        assertThat(request.getEndpointURI()).isEqualTo(new URI("https://c2id.com/login"));
    }

    @Test
    public void testBuilderWithWithRequestObject()
            throws Exception {

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType("code", "id_token"),
                new Scope("openid", "email"),
                new ClientID("123"),
                new URI("https://client.com/cb")).
                nonce(new Nonce("xyz")).
                requestObject(JWTParser.parse(EXAMPLE_JWT_STRING)).
                build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code", "id_token"));
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
        assertThat(request.getScope()).isEqualTo(new Scope("openid", "email"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getRedirectionURI()).isEqualTo(new URI("https://client.com/cb"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("xyz"));
        assertThat(request.getRequestObject().getParsedString()).isEqualTo(EXAMPLE_JWT_STRING);
        assertThat(request.getMaxAge()).isEqualTo(-1);
    }

    @Test
    public void testBuilderWithRequestURI()
            throws Exception {

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType("code", "id_token"),
                new Scope("openid", "email"),
                new ClientID("123"),
                new URI("https://client.com/cb")).
                requestURI(new URI("https://client.com/request#123")).
                nonce(new Nonce("xyz")).
                build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code", "id_token"));
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
        assertThat(request.getScope()).isEqualTo(new Scope("openid", "email"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getRedirectionURI()).isEqualTo(new URI("https://client.com/cb"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("xyz"));
        assertThat(request.getRequestURI()).isEqualTo(new URI("https://client.com/request#123"));
        assertThat(request.getMaxAge()).isEqualTo(-1);
    }

    @Test
    public void testParseMissingRedirectionURI() {

        String query = "response_type=id_token%20token" +
                "&client_id=s6BhdRkqt3" +
                "&scope=openid%20profile" +
                "&state=af0ifjsldkj" +
                "&nonce=n-0S6_WzA2Mj";

        try {
            AuthenticationRequest.parse(query);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing \"redirect_uri\" parameter");
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"redirect_uri\" parameter");
            assertThat(e.getResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
            assertThat(e.getErrorObject().getURI()).isNull();
        }
    }

    @Test
    public void testParseMissingScope() {

        String query = "response_type=id_token%20token" +
                "&client_id=s6BhdRkqt3" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&state=af0ifjsldkj";

        try {
            AuthenticationRequest.parse(query);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing \"scope\" parameter");
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"scope\" parameter");
            assertThat(e.getResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
            assertThat(e.getErrorObject().getURI()).isNull();
        }
    }

    @Test
    public void testParseMissingScopeOpenIDValue() {

        String query = "response_type=code" +
                "&client_id=s6BhdRkqt3" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&scope=profile" +
                "&state=af0ifjsldkj";

        try {
            AuthenticationRequest.parse(query);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("The scope must include an \"openid\" value");
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: The scope must include an \"openid\" value");
            assertThat(e.getResponseMode()).isEqualTo(ResponseMode.QUERY);
            assertThat(e.getErrorObject().getURI()).isNull();
        }
    }

    @Test
    public void testParseMissingNonceInImplicitFlow() {

        String query = "response_type=id_token%20token" +
                "&client_id=s6BhdRkqt3" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&scope=openid%20profile" +
                "&state=af0ifjsldkj";

        try {
            AuthenticationRequest.parse(query);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing \"nonce\" parameter: Required in the implicit and hybrid flows");
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"nonce\" parameter: Required in the implicit and hybrid flows");
            assertThat(e.getResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
            assertThat(e.getErrorObject().getURI()).isNull();
        }
    }

    @Test
    public void testParseInvalidDisplay() {

        String query = "response_type=code" +
                "&client_id=s6BhdRkqt3" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&scope=openid%20profile" +
                "&state=af0ifjsldkj" +
                "&display=mobile";

        try {
            AuthenticationRequest.parse(query);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Invalid \"display\" parameter: Unknown display type: mobile");
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Invalid \"display\" parameter: Unknown display type: mobile");
            assertThat(e.getResponseMode()).isEqualTo(ResponseMode.QUERY);
            assertThat(e.getErrorObject().getURI()).isNull();
        }
    }

    @Test
    public void testParseInvalidMaxAge() {

        String query = "response_type=code" +
                "&client_id=s6BhdRkqt3" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&scope=openid%20profile" +
                "&state=af0ifjsldkj" +
                "&max_age=zero";

        try {
            AuthenticationRequest.parse(query);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Invalid \"max_age\" parameter: zero");
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Invalid \"max_age\" parameter: zero");
            assertThat(e.getResponseMode()).isEqualTo(ResponseMode.QUERY);
            assertThat(e.getErrorObject().getURI()).isNull();
        }
    }

    @Test
    public void testParseInvalidIDTokenHint() {

        String query = "response_type=code" +
                "&client_id=s6BhdRkqt3" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&scope=openid%20profile" +
                "&state=af0ifjsldkj" +
                "&id_token_hint=ey...";

        try {
            AuthenticationRequest.parse(query);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Invalid \"id_token_hint\" parameter: Invalid unsecured/JWS/JWE header: Unexpected exception: Invalid token=EOF at (line no=1, column no=2, offset=1). Expected tokens are: [STRING, CURLYCLOSE]");
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Invalid \"id_token_hint\" parameter: Invalid unsecured/JWS/JWE header: Unexpected exception: Invalid token=EOF at (line no=1, column no=2, offset=1). Expected tokens are: [STRING, CURLYCLOSE]");
            assertThat(e.getResponseMode()).isEqualTo(ResponseMode.QUERY);
            assertThat(e.getErrorObject().getURI()).isNull();
        }
    }

    @Test
    public void testParseFromURI()
            throws Exception {

        URI uri = new URI("https://c2id.com/login?" +
                "response_type=id_token%20token" +
                "&client_id=s6BhdRkqt3" +
                "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                "&scope=openid%20profile" +
                "&state=af0ifjsldkj" +
                "&nonce=n-0S6_WzA2Mj");

        AuthenticationRequest request = AuthenticationRequest.parse(uri);

        assertThat(request.getEndpointURI()).isEqualTo(new URI("https://c2id.com/login"));
        assertThat(request.getResponseType()).isEqualTo(new ResponseType("id_token", "token"));
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
        assertThat(request.getClientID()).isEqualTo(new ClientID("s6BhdRkqt3"));
        assertThat(request.getRedirectionURI()).isEqualTo(new URI("https://client.example.org/cb"));
        assertThat(request.getScope()).isEqualTo(new Scope("openid", "profile"));
        assertThat(request.getState()).isEqualTo(new State("af0ifjsldkj"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("n-0S6_WzA2Mj"));
        assertThat(request.getMaxAge()).isEqualTo(-1);
    }

    @Test
    public void testParseRequestURIWithRedirectURI()
            throws Exception {

        // See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issue/113/authenticationrequest-fails-to-parse

        // Example from http://openid.net/specs/openid-connect-core-1_0.html#UseRequestUri
        String query = "response_type=code%20id_token" +
                "&client_id=s6BhdRkqt3" +
                "&request_uri=https%3A%2F%2Fclient.example.org%2Frequest.jwt" +
                "%23GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM" +
                "&state=af0ifjsldkj&nonce=n-0S6_WzA2Mj" +
                "&scope=openid";

        AuthenticationRequest request = AuthenticationRequest.parse(query);

        assertThat(new ResponseType("code", "id_token")).isEqualTo(request.getResponseType());
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
        assertThat(new ClientID("s6BhdRkqt3")).isEqualTo(request.getClientID());
        assertThat(new URI("https://client.example.org/request.jwt#GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM")).isEqualTo(request.getRequestURI());
        assertThat(new State("af0ifjsldkj")).isEqualTo(request.getState());
        assertThat(new Nonce("n-0S6_WzA2Mj")).isEqualTo(request.getNonce());
        assertThat(Scope.parse("openid")).isEqualTo(request.getScope());
        assertThat(request.getMaxAge()).isEqualTo(-1);
    }

    @Test
    public void testBuilderWithRedirectURIInRequestURI()
            throws Exception {

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType("code", "id_token"),
                new Scope("openid"),
                new ClientID("s6BhdRkqt3"),
                null) // redirect_uri
                .state(new State("af0ifjsldkj"))
                .nonce(new Nonce("n-0S6_WzA2Mj"))
                .requestURI(new URI("https://client.example.org/request.jwt#GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM"))
                .build();

        assertThat(new ResponseType("code", "id_token")).isEqualTo(request.getResponseType());
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
        assertThat(new ClientID("s6BhdRkqt3")).isEqualTo(request.getClientID());
        assertThat(new URI("https://client.example.org/request.jwt#GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM")).isEqualTo(request.getRequestURI());
        assertThat(new State("af0ifjsldkj")).isEqualTo(request.getState());
        assertThat(new Nonce("n-0S6_WzA2Mj")).isEqualTo(request.getNonce());
        assertThat(Scope.parse("openid")).isEqualTo(request.getScope());
    }

    @Test
    public void testRequireNonceInHybridFlow()
            throws Exception {

        // See https://bitbucket.org/openid/connect/issues/972/nonce-requirement-in-hybrid-auth-request

        // Spec discussion about nonce in hybrid flow https://bitbucket.org/openid/connect/issues/972/nonce-requirement-in-hybrid-auth-request

        // Test constructor

        new AuthenticationRequest.Builder(
                ResponseType.parse("code"),
                new Scope("openid"),
                new ClientID("s6BhdRkqt3"),
                URI.create("https://example.com/cb")) // redirect_uri
                .state(new State("af0ifjsldkj"))
                .build();

        try {
            new AuthenticationRequest.Builder(
                    ResponseType.parse("code id_token"),
                    new Scope("openid"),
                    new ClientID("s6BhdRkqt3"),
                    URI.create("https://example.com/cb")) // redirect_uri
                    .state(new State("af0ifjsldkj"))
                    .build();
            fail();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo("Nonce is required in implicit / hybrid protocol flow");
        }

        try {
            new AuthenticationRequest.Builder(
                    ResponseType.parse("code id_token token"),
                    new Scope("openid"),
                    new ClientID("s6BhdRkqt3"),
                    URI.create("https://example.com/cb")) // redirect_uri
                    .state(new State("af0ifjsldkj"))
                    .build();
            fail();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo("Nonce is required in implicit / hybrid protocol flow");
        }

        try {
            new AuthenticationRequest.Builder(
                    ResponseType.parse("id_token token"),
                    new Scope("openid"),
                    new ClientID("s6BhdRkqt3"),
                    URI.create("https://example.com/cb")) // redirect_uri
                    .state(new State("af0ifjsldkj"))
                    .build();
            fail();
        } catch (IllegalStateException e) {
            assertThat(e.getMessage()).isEqualTo("Nonce is required in implicit / hybrid protocol flow");
        }

        // Test static parse method
        try {
            AuthenticationRequest.parse(new URI(
                    "https://server.example.com" +
                            "/authorize?" +
                            "response_type=code%20id_token" +
                            "&client_id=s6BhdRkqt3" +
                            "&redirect_uri=https%3A%2F%2Fclient.example.org%2Fcb" +
                            "&scope=openid%20profile" +
                            "&state=af0ifjsldkj"));
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Missing \"nonce\" parameter: Required in the implicit and hybrid flows");
            assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_REQUEST.getCode());
            assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid request: Missing \"nonce\" parameter: Required in the implicit and hybrid flows");
            assertThat(e.getClientID()).isEqualTo(new ClientID("s6BhdRkqt3"));
            assertThat(e.getRedirectionURI()).isEqualTo(new URI("https://client.example.org/cb"));
            assertThat(e.getResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
            assertThat(e.getState()).isEqualTo(new State("af0ifjsldkj"));
        }
    }


    // See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
    @Test
    public void testParseWithEncodedEqualsChar()
            throws Exception {

        URI redirectURI = URI.create("https://client.com/in?app=123");

        String encodedRedirectURI = URLEncoder.encode(redirectURI.toString(), "UTF-8");

        URI requestURI = URI.create("https://server.example.com/authorize?" +
                "response_type=id_token%20token" +
                "&client_id=s6BhdRkqt3" +
                "&scope=openid%20profile" +
                "&state=af0ifjsldkj" +
                "&nonce=n-0S6_WzA2Mj" +
                "&redirect_uri=" + encodedRedirectURI);

        AuthenticationRequest request = AuthenticationRequest.parse(requestURI);

        assertThat(request.getResponseType()).isEqualTo(ResponseType.parse("id_token token"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("s6BhdRkqt3"));
        assertThat(request.getState()).isEqualTo(new State("af0ifjsldkj"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("n-0S6_WzA2Mj"));
        assertThat(request.getMaxAge()).isEqualTo(-1);
        assertThat(request.getRedirectionURI()).isEqualTo(redirectURI);
    }

    @Test
    public void testParsePKCEExample()
            throws Exception {

        URI redirectURI = URI.create("https://client.com/cb");

        String encodedRedirectURI = URLEncoder.encode(redirectURI.toString(), "UTF-8");

        URI requestURI = URI.create("https://server.example.com/authorize?" +
                "response_type=id_token%20token" +
                "&client_id=s6BhdRkqt3" +
                "&scope=openid%20profile" +
                "&state=af0ifjsldkj" +
                "&nonce=n-0S6_WzA2Mj" +
                "&redirect_uri=" + encodedRedirectURI +
                "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" +
                "&code_challenge_method=S256");

        AuthenticationRequest request = AuthenticationRequest.parse(requestURI);

        assertThat(request.getResponseType()).isEqualTo(ResponseType.parse("id_token token"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("s6BhdRkqt3"));
        assertThat(request.getState()).isEqualTo(new State("af0ifjsldkj"));
        assertThat(request.getNonce()).isEqualTo(new Nonce("n-0S6_WzA2Mj"));
        assertThat(request.getMaxAge()).isEqualTo(-1);
        assertThat(request.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(request.getCodeChallenge().getValue()).isEqualTo("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assertThat(request.getCodeChallengeMethod()).isEqualTo(CodeChallengeMethod.S256);
    }

    @Test
    public void testParseWithCustomParams()
            throws Exception {

        String q = "https://example.com:9091/oidc-login?client_id=am6bae3a&response_type=id_token+token&redirect_uri=https%3A%2F%2Fexample.com%3A9090%2Fexample%2FimplicitFlow&scope=openid&nonce=CvJam5c9fpY&claims=%7B%22id_token%22%3A%7B%22given_name%22%3Anull%2C%22family_name%22%3Anull%7D%7D&scope=openid&language=zh&context=MS-GLOBAL01&response_mode=json";

        AuthenticationRequest r = AuthenticationRequest.parse(URI.create(q));

        assertThat(r.getClientID()).isEqualTo(new ClientID("am6bae3a"));
        assertThat(r.getResponseType()).isEqualTo(new ResponseType("token", "id_token"));
        assertThat(r.getResponseMode()).isEqualTo(new ResponseMode("json"));
        assertThat(r.getScope()).isEqualTo(new Scope("openid"));
        assertThat(r.getNonce()).isEqualTo(new Nonce("CvJam5c9fpY"));
        assertThat(r.getMaxAge()).isEqualTo(-1);
        assertThat(r.getClaims().getIDTokenClaimNames().contains("family_name")).isTrue();
        assertThat(r.getClaims().getIDTokenClaimNames().contains("given_name")).isTrue();
        assertThat(r.getClaims().getIDTokenClaimNames()).hasSize(2);
        assertThat(r.getRedirectionURI()).isEqualTo(URI.create("https://example.com:9090/example/implicitFlow"));
        assertThat(r.getCustomParameter("context")).isEqualTo(Collections.singletonList("MS-GLOBAL01")); // custom
        assertThat(r.getCustomParameter("language")).isEqualTo(Collections.singletonList("zh")); // custom
    }

    @Test
    public void testSignedAuthRequest()
            throws Exception {

        JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder()
                .claim("response_type", "code")
                .claim("scope", "openid email")
                .claim("code_challenge_method", "S256")
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("1").build(),
                jwtClaims);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair rsaKeyPair = keyPairGenerator.generateKeyPair();

        jwt.sign(new RSASSASigner(rsaKeyPair.getPrivate()));

        String jwtString = jwt.serialize();

        CodeVerifier pkceVerifier = new CodeVerifier();

        URI authRequest = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("myapp://openid-connect-callback"))
                .state(new State())
                .codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
                .requestObject(jwt)
                .endpointURI(URI.create("https://openid.c2id.com"))
                .build()
                .toURI();


        Base64URLValue fragment = Base64URLValue.encode(MessageDigest.getInstance("SHA-256").digest(jwtString.getBytes(StandardCharsets.UTF_8)));

        URI requestURI = URI.create("https://myapp.io/request.jwt+" + fragment);

        authRequest = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("myapp://openid-connect-callback"))
                .state(new State())
                .codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
                .requestURI(requestURI)
                .endpointURI(URI.create("https://openid.c2id.com"))
                .build()
                .toURI();

    }

    @Test
    public void testBuilder_PKCE_null() {

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .codeChallenge((CodeVerifier) null, null)
                .build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI()).isNull();
        assertThat(request.getRedirectionURI()).isEqualTo(URI.create("https://example.com/cb"));
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(request.getScope()).isEqualTo(new Scope("openid"));
        assertThat(request.getState()).isNull();
        assertThat(request.getCodeChallenge()).isNull();
        assertThat(request.getCodeChallengeMethod()).isNull();
        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testBuilder_PKCE_null_deprecated() {

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .codeChallenge((CodeChallenge) null, null)
                .build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI()).isNull();
        assertThat(request.getRedirectionURI()).isEqualTo(URI.create("https://example.com/cb"));
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(request.getScope()).isEqualTo(new Scope("openid"));
        assertThat(request.getState()).isNull();
        assertThat(request.getCodeChallenge()).isNull();
        assertThat(request.getCodeChallengeMethod()).isNull();
        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testBuilder_PKCE_plain_default() {

        CodeVerifier pkceVerifier = new CodeVerifier();

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .codeChallenge(pkceVerifier, null)
                .build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI()).isNull();
        assertThat(request.getRedirectionURI()).isEqualTo(URI.create("https://example.com/cb"));
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(request.getScope()).isEqualTo(new Scope("openid"));
        assertThat(request.getState()).isNull();
        assertThat(request.getCodeChallenge()).isEqualTo(CodeChallenge.compute(CodeChallengeMethod.PLAIN, pkceVerifier));
        assertThat(request.getCodeChallengeMethod()).isEqualTo(CodeChallengeMethod.PLAIN);
        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testBuilder_PKCE_plain() {

        CodeVerifier pkceVerifier = new CodeVerifier();

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .codeChallenge(pkceVerifier, CodeChallengeMethod.PLAIN)
                .build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI()).isNull();
        assertThat(request.getRedirectionURI()).isEqualTo(URI.create("https://example.com/cb"));
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(request.getScope()).isEqualTo(new Scope("openid"));
        assertThat(request.getState()).isNull();
        assertThat(request.getCodeChallenge()).isEqualTo(CodeChallenge.compute(CodeChallengeMethod.PLAIN, pkceVerifier));
        assertThat(request.getCodeChallengeMethod()).isEqualTo(CodeChallengeMethod.PLAIN);
        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testBuilder_PKCE_S256() {

        CodeVerifier pkceVerifier = new CodeVerifier();

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .codeChallenge(pkceVerifier, CodeChallengeMethod.S256)
                .build();

        assertThat(request.getResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(request.getClientID()).isEqualTo(new ClientID("123"));
        assertThat(request.getEndpointURI()).isNull();
        assertThat(request.getRedirectionURI()).isEqualTo(URI.create("https://example.com/cb"));
        assertThat(request.getResponseMode()).isNull();
        assertThat(request.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
        assertThat(request.getScope()).isEqualTo(new Scope("openid"));
        assertThat(request.getState()).isNull();
        assertThat(request.getCodeChallenge()).isEqualTo(CodeChallenge.compute(CodeChallengeMethod.S256, pkceVerifier));
        assertThat(request.getCodeChallengeMethod()).isEqualTo(CodeChallengeMethod.S256);
        assertThat(request.getCustomParameters().isEmpty()).isTrue();
    }

    @Test
    public void testCopyConstructorBuilder_requestObject()
            throws Exception {

        ClaimsRequest claims = new ClaimsRequest();
        claims.addIDTokenClaim("name");

        AuthenticationRequest in = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                new URI("https://example.com/cb"))
                .state(new State())
                .nonce(new Nonce())
                .display(Display.POPUP)
                .prompt(new Prompt(Prompt.Type.NONE))
                .maxAge(900)
                .idTokenHint(JWTParser.parse(EXAMPLE_JWT_STRING))
                .loginHint("alice@wonderland.net")
                .acrValues(Arrays.asList(new ACR("0"), new ACR("1")))
                .claims(claims)
                .requestObject(JWTParser.parse(EXAMPLE_JWT_STRING))
                .responseMode(ResponseMode.FORM_POST)
                .codeChallenge(new CodeVerifier(), CodeChallengeMethod.S256)
                .customParameter("apples", "10")
                .endpointURI(new URI("https://c2id.com/login"))
                .build();

        AuthenticationRequest out = new AuthenticationRequest.Builder(in).build();

        assertThat(out.getResponseType()).isEqualTo(in.getResponseType());
        assertThat(out.getScope()).isEqualTo(in.getScope());
        assertThat(out.getClientID()).isEqualTo(in.getClientID());
        assertThat(out.getRedirectionURI()).isEqualTo(in.getRedirectionURI());
        assertThat(out.getState()).isEqualTo(in.getState());
        assertThat(out.getNonce()).isEqualTo(in.getNonce());
        assertThat(out.getDisplay()).isEqualTo(in.getDisplay());
        assertThat(out.getPrompt()).isEqualTo(in.getPrompt());
        assertThat(out.getMaxAge()).isEqualTo(in.getMaxAge());
        assertThat(out.getIDTokenHint()).isEqualTo(in.getIDTokenHint());
        assertThat(out.getLoginHint()).isEqualTo(in.getLoginHint());
        assertThat(out.getACRValues()).isEqualTo(in.getACRValues());
        assertThat(out.getClaims()).isEqualTo(in.getClaims());
        assertThat(out.getRequestObject()).isEqualTo(in.getRequestObject());
        assertThat(out.getRequestURI()).isEqualTo(in.getRequestURI());
        assertThat(out.getResponseMode()).isEqualTo(in.getResponseMode());
        assertThat(out.getCodeChallenge()).isEqualTo(in.getCodeChallenge());
        assertThat(out.getCodeChallengeMethod()).isEqualTo(in.getCodeChallengeMethod());
        assertThat(out.getCustomParameters()).isEqualTo(in.getCustomParameters());
        assertThat(out.getEndpointURI()).isEqualTo(in.getEndpointURI());
    }

    @Test
    public void testCopyConstructorBuilder_requesURI()
            throws Exception {

        ClaimsRequest claims = new ClaimsRequest();
        claims.addIDTokenClaim("name");

        AuthenticationRequest in = new AuthenticationRequest.Builder(
                new ResponseType("code"),
                new Scope("openid"),
                new ClientID("123"),
                new URI("https://example.com/cb"))
                .state(new State())
                .nonce(new Nonce())
                .display(Display.POPUP)
                .prompt(new Prompt(Prompt.Type.NONE))
                .maxAge(900)
                .idTokenHint(JWTParser.parse(EXAMPLE_JWT_STRING))
                .loginHint("alice@wonderland.net")
                .acrValues(Arrays.asList(new ACR("0"), new ACR("1")))
                .claims(claims)
                .requestURI(new URI("https://example.com/request.jwt"))
                .responseMode(ResponseMode.FORM_POST)
                .codeChallenge(new CodeVerifier(), CodeChallengeMethod.S256)
                .customParameter("apples", "10")
                .endpointURI(new URI("https://c2id.com/login"))
                .build();

        AuthenticationRequest out = new AuthenticationRequest.Builder(in).build();

        assertThat(out.getResponseType()).isEqualTo(in.getResponseType());
        assertThat(out.getScope()).isEqualTo(in.getScope());
        assertThat(out.getClientID()).isEqualTo(in.getClientID());
        assertThat(out.getRedirectionURI()).isEqualTo(in.getRedirectionURI());
        assertThat(out.getState()).isEqualTo(in.getState());
        assertThat(out.getNonce()).isEqualTo(in.getNonce());
        assertThat(out.getDisplay()).isEqualTo(in.getDisplay());
        assertThat(out.getPrompt()).isEqualTo(in.getPrompt());
        assertThat(out.getMaxAge()).isEqualTo(in.getMaxAge());
        assertThat(out.getIDTokenHint()).isEqualTo(in.getIDTokenHint());
        assertThat(out.getLoginHint()).isEqualTo(in.getLoginHint());
        assertThat(out.getACRValues()).isEqualTo(in.getACRValues());
        assertThat(out.getClaims()).isEqualTo(in.getClaims());
        assertThat(out.getRequestObject()).isEqualTo(in.getRequestObject());
        assertThat(out.getRequestURI()).isEqualTo(in.getRequestURI());
        assertThat(out.getResponseMode()).isEqualTo(in.getResponseMode());
        assertThat(out.getCodeChallenge()).isEqualTo(in.getCodeChallenge());
        assertThat(out.getCodeChallengeMethod()).isEqualTo(in.getCodeChallengeMethod());
        assertThat(out.getCustomParameters()).isEqualTo(in.getCustomParameters());
        assertThat(out.getEndpointURI()).isEqualTo(in.getEndpointURI());
    }

    @Test
    public void testQueryParamsInEndpoint()
            throws Exception {

        URI endpoint = new URI("https://c2id.com/login?foo=bar");

        AuthenticationRequest request = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .endpointURI(endpoint)
                .build();

        // query parameters belonging to the authz endpoint not included here
        Map<String, List<String>> requestParameters = request.toParameters();
        assertThat(requestParameters.get("response_type")).isEqualTo(Collections.singletonList("code"));
        assertThat(requestParameters.get("client_id")).isEqualTo(Collections.singletonList("123"));
        assertThat(requestParameters.get("scope")).isEqualTo(Collections.singletonList("openid"));
        assertThat(requestParameters.get("redirect_uri")).isEqualTo(Collections.singletonList("https://example.com/cb"));
        assertThat(requestParameters).hasSize(4);

        Map<String, List<String>> queryParams = URLUtils.parseParameters(request.toQueryString());
        assertThat(queryParams.get("foo")).isEqualTo(Collections.singletonList("bar"));
        assertThat(queryParams.get("response_type")).isEqualTo(Collections.singletonList("code"));
        assertThat(queryParams.get("client_id")).isEqualTo(Collections.singletonList("123"));
        assertThat(queryParams.get("scope")).isEqualTo(Collections.singletonList("openid"));
        assertThat(queryParams.get("redirect_uri")).isEqualTo(Collections.singletonList("https://example.com/cb"));
        assertThat(queryParams).hasSize(5);

        URI redirectToAS = request.toURI();

        Map<String, List<String>> finalParameters = URLUtils.parseParameters(redirectToAS.getQuery());
        assertThat(finalParameters.get("foo")).isEqualTo(Collections.singletonList("bar"));
        assertThat(finalParameters.get("response_type")).isEqualTo(Collections.singletonList("code"));
        assertThat(finalParameters.get("client_id")).isEqualTo(Collections.singletonList("123"));
        assertThat(finalParameters.get("scope")).isEqualTo(Collections.singletonList("openid"));
        assertThat(finalParameters.get("redirect_uri")).isEqualTo(Collections.singletonList("https://example.com/cb"));
        assertThat(finalParameters).hasSize(5);
    }

    @Test
    public void testToJWTClaimsSet() throws java.text.ParseException {

        AuthenticationRequest ar = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .state(new State())
                .build();

        JWTClaimsSet jwtClaimsSet = ar.toJWTClaimsSet();

        assertThat(jwtClaimsSet.getStringClaim("response_type")).isEqualTo(ar.getResponseType().toString());
        assertThat(jwtClaimsSet.getStringClaim("client_id")).isEqualTo(ar.getClientID().toString());
        assertThat(jwtClaimsSet.getStringClaim("scope")).isEqualTo(ar.getScope().toString());
        assertThat(jwtClaimsSet.getStringClaim("redirect_uri")).isEqualTo(ar.getRedirectionURI().toString());
        assertThat(jwtClaimsSet.getStringClaim("state")).isEqualTo(ar.getState().toString());

        assertThat(jwtClaimsSet.getClaims()).hasSize(5);
    }

    @Test
    public void testToJWTClaimsSet_withMaxAge() throws java.text.ParseException {

        AuthenticationRequest ar = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .state(new State())
                .maxAge(3600)
                .build();

        JWTClaimsSet jwtClaimsSet = ar.toJWTClaimsSet();

        assertThat(jwtClaimsSet.getStringClaim("response_type")).isEqualTo(ar.getResponseType().toString());
        assertThat(jwtClaimsSet.getStringClaim("client_id")).isEqualTo(ar.getClientID().toString());
        assertThat(jwtClaimsSet.getStringClaim("scope")).isEqualTo(ar.getScope().toString());
        assertThat(jwtClaimsSet.getStringClaim("redirect_uri")).isEqualTo(ar.getRedirectionURI().toString());
        assertThat(jwtClaimsSet.getStringClaim("state")).isEqualTo(ar.getState().toString());
        assertThat(jwtClaimsSet.getIntegerClaim("max_age").intValue()).isEqualTo(ar.getMaxAge());

        assertThat(jwtClaimsSet.getClaims()).hasSize(6);
    }

    @Test
    public void testToJWTClaimsSet_withMaxAge_withMultipleResourceParams() throws java.text.ParseException {

        AuthenticationRequest ar = new AuthenticationRequest.Builder(
                new ResponseType(ResponseType.Value.CODE),
                new Scope("openid"),
                new ClientID("123"),
                URI.create("https://example.com/cb"))
                .state(new State())
                .maxAge(3600)
                .resources(URI.create("https://one.rs.com"), URI.create("https://two.rs.com"))
                .build();

        JWTClaimsSet jwtClaimsSet = ar.toJWTClaimsSet();

        assertThat(jwtClaimsSet.getStringClaim("response_type")).isEqualTo(ar.getResponseType().toString());
        assertThat(jwtClaimsSet.getStringClaim("client_id")).isEqualTo(ar.getClientID().toString());
        assertThat(jwtClaimsSet.getStringClaim("scope")).isEqualTo(ar.getScope().toString());
        assertThat(jwtClaimsSet.getStringClaim("redirect_uri")).isEqualTo(ar.getRedirectionURI().toString());
        assertThat(jwtClaimsSet.getStringClaim("state")).isEqualTo(ar.getState().toString());
        assertThat(jwtClaimsSet.getIntegerClaim("max_age").intValue()).isEqualTo(ar.getMaxAge());
        assertThat(jwtClaimsSet.getStringListClaim("resource").get(0)).isEqualTo(ar.getResources().get(0).toString());
        assertThat(jwtClaimsSet.getStringListClaim("resource").get(1)).isEqualTo(ar.getResources().get(1).toString());
        assertThat(jwtClaimsSet.getStringListClaim("resource")).hasSize(ar.getResources().size());

        assertThat(jwtClaimsSet.getClaims()).hasSize(7);
    }

    @Test
    public void testBuilder_requestURI_minimal() throws OAuth2JSONParseException {

        URI endpointURI = URI.create("https://c2id.com/login");
        URI requestURI = URI.create("urn:requests:ahy4ohgo");

        AuthenticationRequest ar = new AuthenticationRequest.Builder(requestURI)
                .endpointURI(endpointURI)
                .build();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isEqualTo(requestURI);

        assertThat(ar.specifiesRequestObject()).isTrue();

        assertThat(ar.toURI().toString()).isEqualTo("https://c2id.com/login?request_uri=urn%3Arequests%3Aahy4ohgo");

        ar = AuthenticationRequest.parse(ar.toURI());

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestURI()).isEqualTo(requestURI);
    }

    @Test
    public void testBuilder_requestURI_coreTopLevelParams() {

        URI requestURI = URI.create("urn:requests:ahy4ohgo");
        ResponseType rt = new ResponseType("code");
        Scope scope = new Scope("openid");
        ClientID clientID = new ClientID("123");
        URI redirectURI = URI.create("https://example.com/cb");

        AuthenticationRequest ar = new AuthenticationRequest.Builder(requestURI)
                .responseType(rt)
                .scope(scope)
                .clientID(clientID)
                .redirectionURI(redirectURI)
                .build();

        assertThat(ar.getRequestURI()).isEqualTo(requestURI);
        assertThat(ar.specifiesRequestObject()).isTrue();

        assertThat(ar.getResponseType()).isEqualTo(rt);
        assertThat(ar.getScope()).isEqualTo(scope);
        assertThat(ar.getClientID()).isEqualTo(clientID);
        assertThat(ar.getRedirectionURI()).isEqualTo(redirectURI);

        try {
            new AuthenticationRequest.Builder(requestURI).responseType(null);
            fail("Core response_type when set not null");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The response type must not be null");
        }

        try {
            new AuthenticationRequest.Builder(requestURI).scope(null);
            fail("Core scope when set not null");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The scope must not be null");
        }

        try {
            new AuthenticationRequest.Builder(requestURI).scope(new Scope("email"));
            fail("Core scope when set must contain openid");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The scope must include an \"openid\" value");
        }

        try {
            new AuthenticationRequest.Builder(requestURI).clientID(null);
            fail("Core client ID when set not null");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The client ID must not be null");
        }

        try {
            new AuthenticationRequest.Builder(requestURI).redirectionURI(null);
            fail("Core redirection URI when set not null");
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The redirection URI must not be null");
        }
    }

    @Test
    public void testBuilder_requestObject_minimal() throws OAuth2JSONParseException {

        URI endpointURI = URI.create("https://c2id.com/login");
        ResponseType rt = new ResponseType("code");
        Scope scope = new Scope("openid");
        ClientID clientID = new ClientID("123");
        URI redirectURI = URI.create("https://example.com/cb");

        AuthenticationRequest ar = new AuthenticationRequest.Builder(rt, scope, clientID, redirectURI)
                .endpointURI(endpointURI)
                .build();

        JWT requestObject = new PlainJWT(ar.toJWTClaimsSet());

        ar = new AuthenticationRequest.Builder(requestObject)
                .endpointURI(endpointURI)
                .build();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestObject()).isEqualTo(requestObject);

        assertThat(ar.toURI().toString()).isEqualTo("https://c2id.com/login?request=eyJhbGciOiJub25lIn0.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6IjEyMyIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY2IiLCJzY29wZSI6Im9wZW5pZCJ9.");

        ar = AuthenticationRequest.parse(ar.toURI());

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestObject().serialize()).isEqualTo(requestObject.serialize());
    }

    @Test
    public void testBuilder_requestObject_minimalTopLevelParams() throws OAuth2JSONParseException {

        URI endpointURI = URI.create("https://c2id.com/login");
        ResponseType rt = new ResponseType("code");
        Scope scope = new Scope("openid");
        ClientID clientID = new ClientID("123");
        URI redirectURI = URI.create("https://example.com/cb");

        AuthenticationRequest ar = new AuthenticationRequest.Builder(rt, scope, clientID, redirectURI)
                .endpointURI(endpointURI)
                .build();

        JWT requestObject = new PlainJWT(ar.toJWTClaimsSet());

        ar = new AuthenticationRequest.Builder(requestObject)
                .endpointURI(endpointURI)
                .build();

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestObject()).isEqualTo(requestObject);

        assertThat(ar.toURI().toString()).isEqualTo("https://c2id.com/login?request=eyJhbGciOiJub25lIn0.eyJyZXNwb25zZV90eXBlIjoiY29kZSIsImNsaWVudF9pZCI6IjEyMyIsInJlZGlyZWN0X3VyaSI6Imh0dHBzOi8vZXhhbXBsZS5jb20vY2IiLCJzY29wZSI6Im9wZW5pZCJ9.");

        ar = AuthenticationRequest.parse(ar.toURI());

        assertThat(ar.getEndpointURI()).isEqualTo(endpointURI);
        assertThat(ar.getRequestObject().serialize()).isEqualTo(requestObject.serialize());
    }

    @Test
    public void testRequestObject_hybridFlow_formPost() throws Exception {

        Issuer op = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("kgt26u4ulfdxm");
        ResponseType rt = new ResponseType("id_token", "token");
        Scope scope = new Scope("openid");
        URI redirectURI = URI.create("https://example.com/cb");
        ResponseMode rm = ResponseMode.FORM_POST;
        State state = new State();
        Nonce nonce = new Nonce();

        AuthenticationRequest securedRequest = new AuthenticationRequest.Builder(rt, scope, clientID, redirectURI)
                .responseMode(rm)
                .state(state)
                .nonce(nonce)
                .build();

        Date exp = new Date((new Date().getTime() / 1000 * 1000) + 60_000L);
        JWTClaimsSet jarClaims = new JWTClaimsSet.Builder(securedRequest.toJWTClaimsSet())
                .expirationTime(exp)
                .audience(op.getValue())
                .build();
        RSAKey rsaJWK = generateKey();

        SignedJWT jar = new SignedJWT(new JWSHeader.Builder((JWSAlgorithm) rsaJWK.getAlgorithm()).keyID(rsaJWK.getKeyID()).build(), jarClaims);
        jar.sign(new RSASSASigner(rsaJWK));

        AuthenticationRequest jarRequest = new AuthenticationRequest.Builder(jar).build();

        Map<String, List<String>> params = jarRequest.toParameters();

        // Selected top level params
        params.put("scope", Collections.singletonList(scope.toString()));
        params.put("response_type", Collections.singletonList(rt.toString()));
        params.put("client_id", Collections.singletonList(clientID.getValue()));

        AuthenticationRequest ar = AuthenticationRequest.parse(params);

        assertThat(ar.getRequestObject().serialize()).isEqualTo(jar.serialize());
        assertThat(ar.getClientID()).isEqualTo(clientID);
        assertThat(ar.getScope()).isEqualTo(scope);
        assertThat(ar.getResponseType()).isEqualTo(rt);
        assertThat(ar.toParameters()).hasSize(4);
    }

    private static RSAKey generateKey() {
        KeyGenerator keyGenerator = new KeyGenerator();
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeySize(2048)
                .withKeyId("s1")
                .build();
        List<AtbashKey> atbashKeys = keyGenerator.generateKeys(generationParameters);

        ListKeyManager keyManager = new ListKeyManager(atbashKeys);

        SelectorCriteria criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PRIVATE).build();
        List<AtbashKey> privateList = keyManager.retrieveKeys(criteria);

        AtbashKey privateKey = privateList.get(0);
        criteria = SelectorCriteria.newBuilder().withAsymmetricPart(AsymmetricPart.PUBLIC).build();

        List<AtbashKey> publicList = keyManager.retrieveKeys(criteria);
        AtbashKey publicKey = publicList.get(0);


        return new RSAKey.Builder((RSAPublicKey) publicKey.getKey()).keyID("kid")
                .privateKey((RSAPrivateKey) privateKey.getKey())
                .algorithm(JWSAlgorithm.RS256)
                .build();


    }

    @Test
    public void testBuilder_nullResponseType() {

        try {
            new AuthenticationRequest.Builder(null, new Scope("openid"), new ClientID("123"), URI.create("https://example.com/cb"));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The response type must not be null");
        }
    }

    @Test
    public void testBuilder_nullScope() {

        try {
            new AuthenticationRequest.Builder(new ResponseType("code"), null, new ClientID("123"), URI.create("https://example.com/cb"));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The scope must not be null");
        }
    }

    @Test
    public void testBuilder_missingOpenIDScopeValue() {

        try {
            new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("email"), new ClientID("123"), URI.create("https://example.com/cb"));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The scope must include an \"openid\" value");
        }
    }

    @Test
    public void testBuilder_nullClientID() {

        try {
            new AuthenticationRequest.Builder(new ResponseType("code"), new Scope("openid"), null, URI.create("https://example.com/cb"));
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The client ID must not be null");
        }
    }
}