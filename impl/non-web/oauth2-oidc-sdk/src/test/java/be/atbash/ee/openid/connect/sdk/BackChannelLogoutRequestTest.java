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


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.JWTID;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.openid.connect.sdk.claims.LogoutTokenClaimsSet;
import be.atbash.ee.openid.connect.sdk.claims.SessionID;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.PlainJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


public class BackChannelLogoutRequestTest {


    private static final RSAKey RSA_JWK;


    private static URI LOGOUT_ENDPOINT_URI = URI.create("https://rp.example.com/logout");


    private static URL LOGOUT_ENDPOINT_URL;


    static {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair kp = gen.generateKeyPair();
            RSA_JWK = new RSAKey.Builder((RSAPublicKey) kp.getPublic())
                    .privateKey((RSAPrivateKey) kp.getPrivate())
                    .keyIDFromThumbprint()
                    .build();

            LOGOUT_ENDPOINT_URL = LOGOUT_ENDPOINT_URI.toURL();

        } catch (NoSuchAlgorithmException | JOSEException | MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }


    private static JWTClaimsSet createLogoutTokenClaimsSet() {

        LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(
                new Issuer(URI.create("https://c2id.com")),
                new Subject("alice"),
                new Audience("123").toSingleAudienceList(),
                new Date(),
                new JWTID(),
                new SessionID(UUID.randomUUID().toString()));

        try {
            return claimsSet.toJWTClaimsSet();
        } catch (OAuth2JSONParseException e) {
            throw new RuntimeException(e);
        }
    }


    private static JWT createSignedLogoutToken() {


        SignedJWT jwt;
        try {
            jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(RSA_JWK.getKeyID())
                            .build(),
                    createLogoutTokenClaimsSet());

            jwt.sign(new RSASSASigner(RSA_JWK.toRSAPrivateKey()));
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }

        return jwt;
    }

    @Test
    public void testLifeCycle()
            throws Exception {

        JWT logoutToken = createSignedLogoutToken();

        BackChannelLogoutRequest request = new BackChannelLogoutRequest(LOGOUT_ENDPOINT_URI, logoutToken);

        assertThat(request.getEndpointURI()).isEqualTo(LOGOUT_ENDPOINT_URI);
        assertThat(request.getLogoutToken()).isEqualTo(logoutToken);

        Map<String, List<String>> params = request.toParameters();
        assertThat(params.get("logout_token")).isEqualTo(Collections.singletonList(logoutToken.serialize()));
        assertThat(params).hasSize(1);

        HTTPRequest httpRequest = request.toHTTPRequest();

        assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.POST);
        assertThat(httpRequest.getContentType().toString()).isEqualTo(CommonContentTypes.APPLICATION_URLENCODED.toString());
        params = httpRequest.getQueryParameters();
        assertThat(params.get("logout_token")).isEqualTo(Collections.singletonList(logoutToken.serialize()));
        assertThat(params).hasSize(1);

        // Parse from HTTP request
        request = BackChannelLogoutRequest.parse(httpRequest);
        assertThat(request.getEndpointURI()).isEqualTo(LOGOUT_ENDPOINT_URI);
        assertThat(request.getLogoutToken().serialize()).isEqualTo(logoutToken.serialize());

        // Parse from URI + parameters
        request = BackChannelLogoutRequest.parse(LOGOUT_ENDPOINT_URI, params);
        assertThat(request.getEndpointURI()).isEqualTo(LOGOUT_ENDPOINT_URI);
        assertThat(request.getLogoutToken().serialize()).isEqualTo(logoutToken.serialize());

        // Parse from parameters
        request = BackChannelLogoutRequest.parse(params);
        assertThat(request.getEndpointURI()).isNull();
        assertThat(request.getLogoutToken().serialize()).isEqualTo(logoutToken.serialize());
    }

    @Test
    public void testParseMissingParams() {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, LOGOUT_ENDPOINT_URL);
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                BackChannelLogoutRequest.parse(httpRequest));

        assertThat(exception.getMessage()).isEqualTo("Missing URI query string");

    }

    @Test
    public void testParseInvalidJWT() {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, LOGOUT_ENDPOINT_URL);
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("logout_token=ey...");

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                BackChannelLogoutRequest.parse(httpRequest));

        assertThat(exception.getMessage()).isEqualTo("Invalid logout token: Invalid unsecured/JWS/JWE header: Unexpected exception: Invalid token=EOF at (line no=1, column no=2, offset=1). Expected tokens are: [STRING, CURLYCLOSE]");

    }

    @Test
    public void testRejectPlainJWT_constructor() {

        URI LOGOUT_ENDPOINT_URI = URI.create("https://rp.example.com/logout");

        PlainJWT jwt = new PlainJWT(createLogoutTokenClaimsSet());

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                new BackChannelLogoutRequest(LOGOUT_ENDPOINT_URI, jwt));

        assertThat(exception.getMessage()).isEqualTo("The logout token must not be unsecured (plain)");

    }

    @Test
    public void testRejectPlainJWT_parse()
            throws Exception {

        PlainJWT jwt = new PlainJWT(createLogoutTokenClaimsSet());

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, LOGOUT_ENDPOINT_URL);
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("logout_token=" + jwt.serialize());

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                BackChannelLogoutRequest.parse(httpRequest));

        assertThat(exception.getMessage()).isEqualTo("The logout token must not be unsecured (plain)");

    }

    @Test
    public void testRejectGET() {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, LOGOUT_ENDPOINT_URL);
        JWT logoutToken = createSignedLogoutToken();
        httpRequest.setQuery("logout_token=" + logoutToken.serialize());

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                BackChannelLogoutRequest.parse(httpRequest));

        assertThat(exception.getMessage()).isEqualTo("HTTP POST required");

    }

    @Test
    public void testIgnoreMissingContentType()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, LOGOUT_ENDPOINT_URL);
        JWT logoutToken = createSignedLogoutToken();
        httpRequest.setQuery("logout_token=" + logoutToken.serialize());

        BackChannelLogoutRequest request = BackChannelLogoutRequest.parse(httpRequest);
        assertThat(request.getEndpointURI()).isEqualTo(LOGOUT_ENDPOINT_URI);
        assertThat(request.getLogoutToken().serialize()).isEqualTo(logoutToken.serialize());
    }

    @Test
    public void testIgnoreMismatchedContentType()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, LOGOUT_ENDPOINT_URL);
        httpRequest.setContentType(CommonContentTypes.APPLICATION_JSON);
        JWT logoutToken = createSignedLogoutToken();
        httpRequest.setQuery("logout_token=" + logoutToken.serialize());

        BackChannelLogoutRequest request = BackChannelLogoutRequest.parse(httpRequest);
        assertThat(request.getEndpointURI()).isEqualTo(LOGOUT_ENDPOINT_URI);
        assertThat(request.getLogoutToken().serialize()).isEqualTo(logoutToken.serialize());
    }
}
