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


import be.atbash.ee.oauth2.sdk.AuthorizationCode;
import be.atbash.ee.oauth2.sdk.ResponseMode;
import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.jarm.JARMUtils;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the authentication success response class.
 */
public class AuthenticationSuccessResponseTest {

    private static final RSAPrivateKey RSA_PRIVATE_KEY;


    private static URI REDIRECT_URI;


    static {

        try {
            REDIRECT_URI = new URI("https://client.com/cb");

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair keyPair = gen.generateKeyPair();
            RSA_PRIVATE_KEY = (RSAPrivateKey) keyPair.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testIDTokenResponse()
            throws Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://c2id.com")
                .audience(Collections.singletonList("https://client.com"))
                .subject("alice")
                .issueTime(new Date(10000L))
                .expirationTime(new Date(20000L))
                .claim("nonce", "123")
                .build();

        SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

        idToken.sign(new MACSigner("01234567890123456789012345678901"));

        AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
                REDIRECT_URI, null, idToken, null, new State("abc"), null, ResponseMode.FRAGMENT);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getRedirectionURI()).isEqualTo(REDIRECT_URI);
        assertThat(response.getIDToken()).isEqualTo(idToken);
        assertThat(response.getAuthorizationCode()).isNull();
        assertThat(response.getAccessToken()).isNull();
        assertThat(response.getState().getValue()).isEqualTo("abc");
        assertThat(response.getSessionState()).isNull();

        assertThat(response.impliedResponseType()).isEqualTo(new ResponseType("id_token"));
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);

        URI responseURI = response.toURI();

        String[] parts = responseURI.toString().split("#");
        assertThat(parts[0]).isEqualTo(REDIRECT_URI.toString());

        response = AuthenticationSuccessResponse.parse(responseURI);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getRedirectionURI()).isEqualTo(REDIRECT_URI);
        assertThat(response.getIDToken().getJWTClaimsSet().getIssuer()).isEqualTo("https://c2id.com");
        assertThat(response.getIDToken().getJWTClaimsSet().getAudience().get(0)).isEqualTo("https://client.com");
        assertThat(response.getIDToken().getJWTClaimsSet().getSubject()).isEqualTo("alice");
        assertThat(response.getIDToken().getJWTClaimsSet().getIssueTime().getTime()).isEqualTo(10000L);
        assertThat(response.getIDToken().getJWTClaimsSet().getExpirationTime().getTime()).isEqualTo(20000L);
        assertThat((String) response.getIDToken().getJWTClaimsSet().getClaim("nonce")).isEqualTo("123");
        assertThat(response.getAuthorizationCode()).isNull();
        assertThat(response.getAccessToken()).isNull();
        assertThat(response.getState().getValue()).isEqualTo("abc");
        assertThat(response.getSessionState()).isNull();
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
    }

    @Test
    public void testCodeIDTokenResponse()
            throws Exception {

        AuthorizationCode code = new AuthorizationCode();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://c2id.com")
                .audience(Collections.singletonList("https://client.com"))
                .subject("alice")
                .issueTime(new Date(10000L))
                .expirationTime(new Date(20000L))
                .claim("nonce", "123")
                .build();

        SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

        idToken.sign(new MACSigner("01234567890123456789012345678901"));

        AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
                REDIRECT_URI, code, idToken, null, new State("abc"), null, ResponseMode.FRAGMENT);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getRedirectionURI()).isEqualTo(REDIRECT_URI);
        assertThat(response.getIDToken()).isEqualTo(idToken);
        assertThat(response.getAuthorizationCode()).isEqualTo(code);
        assertThat(response.getAccessToken()).isNull();
        assertThat(response.getState().getValue()).isEqualTo("abc");
        assertThat(response.getSessionState()).isNull();

        assertThat(response.impliedResponseType()).isEqualTo(new ResponseType("code", "id_token"));
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);

        URI responseURI = response.toURI();

        String[] parts = responseURI.toString().split("#");
        assertThat(parts[0]).isEqualTo(REDIRECT_URI.toString());

        response = AuthenticationSuccessResponse.parse(responseURI);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getRedirectionURI()).isEqualTo(REDIRECT_URI);
        assertThat(response.getIDToken().getJWTClaimsSet().getIssuer()).isEqualTo("https://c2id.com");
        assertThat(response.getIDToken().getJWTClaimsSet().getAudience().get(0)).isEqualTo("https://client.com");
        assertThat(response.getIDToken().getJWTClaimsSet().getSubject()).isEqualTo("alice");
        assertThat(response.getIDToken().getJWTClaimsSet().getIssueTime().getTime()).isEqualTo(10000L);
        assertThat(response.getIDToken().getJWTClaimsSet().getExpirationTime().getTime()).isEqualTo(20000L);
        assertThat((String) response.getIDToken().getJWTClaimsSet().getClaim("nonce")).isEqualTo("123");
        assertThat(response.getAuthorizationCode()).isEqualTo(code);
        assertThat(response.getAccessToken()).isNull();
        assertThat(response.getState().getValue()).isEqualTo("abc");
        assertThat(response.getSessionState()).isNull();
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
    }

    @Test
    public void testCodeIDTokenResponseWithSessionState()
            throws Exception {

        AuthorizationCode code = new AuthorizationCode();

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://c2id.com")
                .audience(Collections.singletonList("https://client.com"))
                .subject("alice")
                .issueTime(new Date(10000L))
                .expirationTime(new Date(20000L))
                .claim("nonce", "123")
                .build();

        SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

        idToken.sign(new MACSigner("01234567890123456789012345678901"));

        AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
                REDIRECT_URI, code, idToken, null, new State("abc"), new State("xyz"), ResponseMode.FRAGMENT);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getRedirectionURI()).isEqualTo(REDIRECT_URI);
        assertThat(response.getIDToken()).isEqualTo(idToken);
        assertThat(response.getAuthorizationCode()).isEqualTo(code);
        assertThat(response.getAccessToken()).isNull();
        assertThat(response.getState().getValue()).isEqualTo("abc");
        assertThat(response.getSessionState().getValue()).isEqualTo("xyz");

        assertThat(response.impliedResponseType()).isEqualTo(new ResponseType("code", "id_token"));
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);

        URI responseURI = response.toURI();

        String[] parts = responseURI.toString().split("#");
        assertThat(parts[0]).isEqualTo(REDIRECT_URI.toString());

        response = AuthenticationSuccessResponse.parse(responseURI);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getRedirectionURI()).isEqualTo(REDIRECT_URI);
        assertThat(response.getIDToken().getJWTClaimsSet().getIssuer()).isEqualTo("https://c2id.com");
        assertThat(response.getIDToken().getJWTClaimsSet().getAudience().get(0)).isEqualTo("https://client.com");
        assertThat(response.getIDToken().getJWTClaimsSet().getSubject()).isEqualTo("alice");
        assertThat(response.getIDToken().getJWTClaimsSet().getIssueTime().getTime()).isEqualTo(10000L);
        assertThat(response.getIDToken().getJWTClaimsSet().getExpirationTime().getTime()).isEqualTo(20000L);
        assertThat((String) response.getIDToken().getJWTClaimsSet().getClaim("nonce")).isEqualTo("123");
        assertThat(response.getAuthorizationCode()).isEqualTo(code);
        assertThat(response.getAccessToken()).isNull();
        assertThat(response.getState().getValue()).isEqualTo("abc");
        assertThat(response.getSessionState().getValue()).isEqualTo("xyz");
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
    }

    @Test
    public void testCodeResponse()
            throws Exception {

        AuthorizationCode code = new AuthorizationCode();

        AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
                REDIRECT_URI, code, null, null, new State("abc"), null, ResponseMode.QUERY);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getRedirectionURI()).isEqualTo(REDIRECT_URI);
        assertThat(response.getIDToken()).isNull();
        assertThat(response.getAuthorizationCode()).isEqualTo(code);
        assertThat(response.getAccessToken()).isNull();
        assertThat(response.getState().getValue()).isEqualTo("abc");
        assertThat(response.getSessionState()).isNull();

        assertThat(response.impliedResponseType()).isEqualTo(new ResponseType("code"));
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);

        URI responseURI = response.toURI();

        String[] parts = responseURI.toString().split("\\?");
        assertThat(parts[0]).isEqualTo(REDIRECT_URI.toString());

        response = AuthenticationSuccessResponse.parse(responseURI);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getRedirectionURI()).isEqualTo(REDIRECT_URI);
        assertThat(response.getIDToken()).isNull();
        assertThat(response.getAuthorizationCode()).isEqualTo(code);
        assertThat(response.getAccessToken()).isNull();
        assertThat(response.getState().getValue()).isEqualTo("abc");
        assertThat(response.getSessionState()).isNull();
        assertThat(response.impliedResponseMode()).isEqualTo(ResponseMode.QUERY);
    }

    @Test
    public void testRedirectionURIWithQueryString()
            throws Exception {
        // See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/140

        URI redirectURI = URI.create("https://example.com/myservice/?action=oidccallback");
        assertThat(redirectURI.getQuery()).isEqualTo("action=oidccallback");

        AuthorizationCode code = new AuthorizationCode();
        State state = new State();

        AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(redirectURI, code, null, null, state, null, ResponseMode.QUERY);

        Map<String, List<String>> params = response.toParameters();
        assertThat(params.get("code")).isEqualTo(Collections.singletonList(code.getValue()));
        assertThat(params.get("state")).isEqualTo(Collections.singletonList(state.getValue()));
        assertThat(params).hasSize(2);

        URI uri = response.toURI();

        params = URLUtils.parseParameters(uri.getQuery());
        assertThat(params.get("action")).isEqualTo(Collections.singletonList("oidccallback"));
        assertThat(params.get("code")).isEqualTo(Collections.singletonList(code.getValue()));
        assertThat(params.get("state")).isEqualTo(Collections.singletonList(state.getValue()));
        assertThat(params).hasSize(3);
    }

	@Test
	public void testJARM_successLifeCycle_query()
		throws Exception {
		
		AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(
			URI.create("https://example.com/cb"),
			new AuthorizationCode(),
			null,
			null,
			new State(),
			null,
			ResponseMode.QUERY_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			successResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		JWT jwt = signedJWT;
		
		AuthenticationSuccessResponse jwtSuccessResponse = new AuthenticationSuccessResponse(
			successResponse.getRedirectionURI(),
			jwt,
			successResponse.getResponseMode());
		
		assertThat(jwtSuccessResponse.getRedirectionURI()).isEqualTo(successResponse.getRedirectionURI());
		assertThat(jwtSuccessResponse.getJWTResponse()).isEqualTo(jwt);
		assertThat(jwtSuccessResponse.getResponseMode()).isEqualTo(successResponse.getResponseMode());
		
		Map<String, List<String>> params = jwtSuccessResponse.toParameters();
		assertThat(MultivaluedMapUtils.getFirstValue(params, "response")).isEqualTo(jwt.serialize());
		assertThat(params).hasSize(1);
		
		URI uri = jwtSuccessResponse.toURI();
		
		assertThat(uri.toString().startsWith(successResponse.getRedirectionURI().toString())).isTrue();
		assertThat(uri.getQuery()).isEqualTo("response=" + jwt.serialize());
		assertThat(uri.getFragment()).isNull();
		
		jwtSuccessResponse = AuthenticationResponseParser.parse(uri).toSuccessResponse();
		assertThat(jwtSuccessResponse.getRedirectionURI()).isEqualTo(successResponse.getRedirectionURI());
		assertThat(jwtSuccessResponse.getJWTResponse().serialize()).isEqualTo(jwt.serialize());
		assertThat(jwtSuccessResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);
	}

	@Test
	public void testJARM_successLifeCycle_fragment()
		throws Exception {
		
		AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(
			URI.create("https://example.com/cb"),
			new AuthorizationCode(),
			null,
			null,
			new State(),
			null,
			ResponseMode.FRAGMENT_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			successResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		JWT jwt = signedJWT;
		
		AuthenticationSuccessResponse jwtSuccessResponse = new AuthenticationSuccessResponse(
			successResponse.getRedirectionURI(),
			jwt,
			successResponse.getResponseMode());
		
		assertThat(jwtSuccessResponse.getRedirectionURI()).isEqualTo(successResponse.getRedirectionURI());
		assertThat(jwtSuccessResponse.getJWTResponse()).isEqualTo(jwt);
		assertThat(jwtSuccessResponse.getResponseMode()).isEqualTo(successResponse.getResponseMode());
		
		Map<String, List<String>> params = jwtSuccessResponse.toParameters();
		assertThat(MultivaluedMapUtils.getFirstValue(params, "response")).isEqualTo(jwt.serialize());
		assertThat(params).hasSize(1);
		
		URI uri = jwtSuccessResponse.toURI();
		
		assertThat(uri.toString().startsWith(successResponse.getRedirectionURI().toString())).isTrue();
		assertThat(uri.getQuery()).isNull();
		assertThat(uri.getFragment()).isEqualTo("response=" + jwt.serialize());
		
		jwtSuccessResponse = AuthenticationResponseParser.parse(uri).toSuccessResponse();
		assertThat(jwtSuccessResponse.getRedirectionURI()).isEqualTo(successResponse.getRedirectionURI());
		assertThat(jwtSuccessResponse.getJWTResponse().serialize()).isEqualTo(jwt.serialize());
		assertThat(jwtSuccessResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);
	}

}
