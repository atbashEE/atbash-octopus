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
import be.atbash.ee.oauth2.sdk.OAuth2Error;
import be.atbash.ee.oauth2.sdk.ResponseMode;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.jarm.JARMUtils;
import be.atbash.ee.oauth2.sdk.jarm.JARMValidator;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the OpenID Connect authentication response parser.
 */
public class AuthenticationResponseParserTest {

    private static final RSAPrivateKey RSA_PRIVATE_KEY;


    private static final RSAPublicKey RSA_PUBLIC_KEY;


    static {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair keyPair = gen.generateKeyPair();
            RSA_PRIVATE_KEY = (RSAPrivateKey) keyPair.getPrivate();
            RSA_PUBLIC_KEY = (RSAPublicKey) keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testParseSuccess()
            throws Exception {

        URI redirectURI = new URI("https://example.com/in");
        AuthorizationCode code = new AuthorizationCode("123");
        State state = new State("xyz");

        AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(
                redirectURI,
                code,
                null,
                null,
                state,
                null,
                null);

        HTTPResponse httpResponse = successResponse.toHTTPResponse();

        AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isTrue();
        assertThat(response.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(response.getState()).isEqualTo(state);

        successResponse = response.toSuccessResponse();
        assertThat(successResponse.getAuthorizationCode()).isEqualTo(code);
        assertThat(successResponse.getState()).isEqualTo(state);
    }

    @Test
    public void testParseError()
            throws Exception {

        URI redirectURI = new URI("https://example.com/in");
        State state = new State("xyz");

        AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse(
                redirectURI,
                OAuth2Error.ACCESS_DENIED,
                state,
                ResponseMode.QUERY);

        assertThat(errorResponse.indicatesSuccess()).isFalse();

        HTTPResponse httpResponse = errorResponse.toHTTPResponse();

        AuthenticationResponse response = AuthenticationResponseParser.parse(httpResponse);

        assertThat(response.indicatesSuccess()).isFalse();
        assertThat(response.getRedirectionURI()).isEqualTo(redirectURI);
        assertThat(response.getState()).isEqualTo(state);

        errorResponse = response.toErrorResponse();
        assertThat(errorResponse.getErrorObject()).isEqualTo(OAuth2Error.ACCESS_DENIED);
        assertThat(errorResponse.getState()).isEqualTo(state);
    }


    // see https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/162/authenticationresponseparser-does-not
    @Test
    public void testParseAbsoluteURI()
            throws Exception {

        URI redirectURI = URI.create("http:///?code=Qcb0Orv1&state=af0ifjsldkj");

        AuthenticationResponse response = AuthenticationResponseParser.parse(redirectURI);

        AuthenticationSuccessResponse successResponse = (AuthenticationSuccessResponse) response;

        assertThat(successResponse.getAuthorizationCode().getValue()).isEqualTo("Qcb0Orv1");
        assertThat(successResponse.getState().getValue()).isEqualTo("af0ifjsldkj");
    }

    @Test
    public void testJARM_parse_queryExample()
            throws Exception {

        URI uri = URI.create("https://client.example.com/cb?" +
                "response=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLm" +
                "V4YW1wbGUuY29tIiwiYXVkIjoiczZCaGRSa3F0MyIsImV4cCI6MTMxMTI4MTk3MCwiY29kZSI6IlB5eU" +
                "ZhdXgybzdRMFlmWEJVMzJqaHcuNUZYU1FwdnI4YWt2OUNlUkRTZDBRQSIsInN0YXRlIjoiUzhOSjd1cW" +
                "s1Zlk0RWpOdlBfR19GdHlKdTZwVXN2SDlqc1luaTlkTUFKdyJ9.HkdJ_TYgwBBj10C-aWuNUiA062Amq" +
                "2b0_oyuc5P0aMTQphAqC2o9WbGSkpfuHVBowlb-zJ15tBvXDIABL_t83q6ajvjtq_pqsByiRK2dLVdUw" +
                "KhW3P_9wjvI0K20gdoTNbNlP9Z41mhart4BqraIoI8e-L_EfAHfhCG_DDDv7Yg");

        AuthenticationResponse response = AuthenticationResponseParser.parse(uri);

        AuthenticationSuccessResponse successResponse = response.toSuccessResponse();
        assertThat(successResponse.getAuthorizationCode()).isNull();
        assertThat(successResponse.getAccessToken()).isNull();
        assertThat(successResponse.getState().getValue()).isEqualTo("S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw");
        assertThat(successResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);

        JWT jwtResponse = successResponse.getJWTResponse();

        JWTClaimsSet jwtClaimsSet = jwtResponse.getJWTClaimsSet();

        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("https://accounts.example.com");
        assertThat(jwtClaimsSet.getAudience().get(0)).isEqualTo("s6BhdRkqt3");
        assertThat(jwtClaimsSet.getExpirationTime().getTime() / 1000L).isEqualTo(1311281970L);
        assertThat(jwtClaimsSet.getStringClaim("code")).isEqualTo("PyyFaux2o7Q0YfXBU32jhw.5FXSQpvr8akv9CeRDSd0QA");
        assertThat(jwtClaimsSet.getStringClaim("state")).isEqualTo("S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw");
        assertThat(jwtClaimsSet.getClaims()).hasSize(5);
    }

    @Test
    public void testJARM_parse_fragmentExample()
            throws Exception {

        URI uri = URI.create("https://client.example.com/cb#" +
                "response=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2FjY291bnRzLm" +
                "V4YW1wbGUuY29tIiwiYXVkIjoiczZCaGRSa3F0MyIsImV4cCI6MTMxMTI4MTk3MCwiYWNjZXNzX3Rva2" +
                "VuIjoiMllvdG5GWkZFanIxekNzaWNNV3BBQSIsInN0YXRlIjoiUzhOSjd1cWs1Zlk0RWpOdlBfR19GdH" +
                "lKdTZwVXN2SDlqc1luaTlkTUFKdyIsInRva2VuX3R5cGUiOiJiZWFyZXIiLCJleHBpcmVzX2luIjoiMz" +
                "YwMCIsInNjb3BlIjoiZXhhbXBsZSJ9.bgHLOu2dlDjtCnvTLK7hTN_JNwoZXEBnbXQx5vd9z17v1Hyzf" +
                "Mqz00Vi002T-SWf2JEs3IVSvAe1xWLIY0TeuaiegklJx_gvB59SQIhXX2ifzRmqPoDdmJGaWZ3tnRyFW" +
                "NnEogJDqGFCo2RHtk8fXkE5IEiBD0g-tN0GS_XnxlE");

        AuthenticationResponse response = AuthenticationResponseParser.parse(uri);

        AuthenticationSuccessResponse successResponse = response.toSuccessResponse();
        assertThat(successResponse.getAuthorizationCode()).isNull();
        assertThat(successResponse.getAccessToken()).isNull();
        assertThat(successResponse.getState().getValue()).isEqualTo("S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw");
        assertThat(successResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);

        JWT jwtResponse = successResponse.getJWTResponse();

        JWTClaimsSet jwtClaimsSet = jwtResponse.getJWTClaimsSet();

        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("https://accounts.example.com");
        assertThat(jwtClaimsSet.getAudience().get(0)).isEqualTo("s6BhdRkqt3");
        assertThat(jwtClaimsSet.getExpirationTime().getTime() / 1000L).isEqualTo(1311281970L);
        assertThat(jwtClaimsSet.getStringClaim("access_token")).isEqualTo("2YotnFZFEjr1zCsicMWpAA");
        assertThat(jwtClaimsSet.getStringClaim("scope")).isEqualTo("example");
        assertThat(jwtClaimsSet.getStringClaim("token_type")).isEqualTo("bearer");
        assertThat(jwtClaimsSet.getStringClaim("expires_in")).isEqualTo("3600");
        assertThat(jwtClaimsSet.getStringClaim("state")).isEqualTo("S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw");
        assertThat(jwtClaimsSet.getClaims()).hasSize(8);
    }

    @Test
    public void testJARM_parse_formPOSTExample()
            throws Exception {

        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.POST, new URL("https://client.example.org/cb"));
        httpRequest.setContentType(CommonContentTypes.APPLICATION_URLENCODED);
        httpRequest.setQuery("response=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2" +
                "FjY291bnRzLmV4YW1wbGUuY29tIiwiYXVkIjoiczZCaGRSa3F0MyIsImV4cCI6MTM" +
                "xMTI4MTk3MCwiYWNjZXNzX3Rva2VuIjoiMllvdG5GWkZFanIxekNzaWNNV3BBQSIs" +
                "InN0YXRlIjoiUzhOSjd1cWs1Zlk0RWpOdlBfR19GdHlKdTZwVXN2SDlqc1luaTlkT" +
                "UFKdyIsInRva2VuX3R5cGUiOiJiZWFyZXIiLCJleHBpcmVzX2luIjoiMzYwMCIsIn" +
                "Njb3BlIjoiZXhhbXBsZSJ9.bgHLOu2dlDjtCnvTLK7hTN_JNwoZXEBnbXQx5vd9z1" +
                "7v1HyzfMqz00Vi002T-SWf2JEs3IVSvAe1xWLIY0TeuaiegklJx_gvB59SQIhXX2i" +
                "fzRmqPoDdmJGaWZ3tnRyFWNnEogJDqGFCo2RHtk8fXkE5IEiBD0g-tN0GS_XnxlE");

        AuthenticationResponse response = AuthenticationResponseParser.parse(httpRequest);

        AuthenticationSuccessResponse successResponse = response.toSuccessResponse();
        assertThat(successResponse.getAuthorizationCode()).isNull();
        assertThat(successResponse.getAccessToken()).isNull();
        assertThat(successResponse.getState().getValue()).isEqualTo("S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw");
        assertThat(successResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);

        JWT jwtResponse = successResponse.getJWTResponse();

        JWTClaimsSet jwtClaimsSet = jwtResponse.getJWTClaimsSet();

        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("https://accounts.example.com");
        assertThat(jwtClaimsSet.getAudience().get(0)).isEqualTo("s6BhdRkqt3");
        assertThat(jwtClaimsSet.getExpirationTime().getTime() / 1000L).isEqualTo(1311281970L);
        assertThat(jwtClaimsSet.getStringClaim("access_token")).isEqualTo("2YotnFZFEjr1zCsicMWpAA");
        assertThat(jwtClaimsSet.getStringClaim("scope")).isEqualTo("example");
        assertThat(jwtClaimsSet.getStringClaim("token_type")).isEqualTo("bearer");
        assertThat(jwtClaimsSet.getStringClaim("expires_in")).isEqualTo("3600");
        assertThat(jwtClaimsSet.getStringClaim("state")).isEqualTo("S8NJ7uqk5fY4EjNvP_G_FtyJu6pUsvH9jsYni9dMAJw");
        assertThat(jwtClaimsSet.getClaims()).hasSize(8);
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
        assertThat(params.size()).isEqualTo(1);

        URI uri = jwtSuccessResponse.toURI();

        assertThat(uri.toString()).startsWith(successResponse.getRedirectionURI().toString());
        assertThat(uri.getQuery()).isEqualTo("response=" + jwt.serialize());
        assertThat(uri.getFragment()).isNull();

        jwtSuccessResponse = AuthenticationResponseParser.parse(uri).toSuccessResponse();
        assertThat(jwtSuccessResponse.getRedirectionURI()).isEqualTo(successResponse.getRedirectionURI());
        assertThat(jwtSuccessResponse.getJWTResponse().serialize()).isEqualTo(jwt.serialize());
        assertThat(jwtSuccessResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);

        // Parse with validator now
        JARMValidator jarmValidator = new JARMValidator(
                new Issuer("https://c2id.com"),
                new ClientID("123"),
                new TestKeySelector(RSA_PUBLIC_KEY));

        AuthenticationSuccessResponse validatedResponse = AuthenticationResponseParser.parse(uri, jarmValidator).toSuccessResponse();

        assertThat(validatedResponse.getAuthorizationCode()).isEqualTo(successResponse.getAuthorizationCode());
        assertThat(validatedResponse.getState()).isEqualTo(successResponse.getState());
    }

    @Test
    public void testJARM_successLifeCycle_fragment()
            throws Exception {

        AuthenticationSuccessResponse successResponse = new AuthenticationSuccessResponse(
                URI.create("https://example.com/cb"),
                null,
                null,
                new BearerAccessToken(),
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
        assertThat(params.size()).isEqualTo(1);

        URI uri = jwtSuccessResponse.toURI();

        assertThat(uri.toString()).startsWith(successResponse.getRedirectionURI().toString());
        assertThat(uri.getQuery()).isNull();
        assertThat(uri.getFragment()).isEqualTo("response=" + jwt.serialize());

        jwtSuccessResponse = AuthenticationResponseParser.parse(uri).toSuccessResponse();
        assertThat(jwtSuccessResponse.getRedirectionURI()).isEqualTo(successResponse.getRedirectionURI());
        assertThat(jwtSuccessResponse.getJWTResponse().serialize()).isEqualTo(jwt.serialize());
        assertThat(jwtSuccessResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);

        // Parse with validator now
        JARMValidator jarmValidator = new JARMValidator(
                new Issuer("https://c2id.com"),
                new ClientID("123"),
                new TestKeySelector(RSA_PUBLIC_KEY));

        AuthenticationSuccessResponse validatedResponse = AuthenticationResponseParser.parse(uri, jarmValidator).toSuccessResponse();

        assertThat(validatedResponse.getAccessToken()).isEqualTo(successResponse.getAccessToken());
        assertThat(validatedResponse.getState()).isEqualTo(successResponse.getState());
    }

    @Test
    public void testJARM_errorLifeCycle_query()
            throws Exception {

        AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse(
                URI.create("https://example.com/cb"),
                OAuth2Error.ACCESS_DENIED,
                new State(),
                ResponseMode.QUERY_JWT);

        JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
                new Issuer("https://c2id.com"),
                new ClientID("123"),
                new Date(),
                errorResponse);

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
        signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));

        JWT jwt = signedJWT;

        AuthenticationErrorResponse jwtErrorResponse = new AuthenticationErrorResponse(
                errorResponse.getRedirectionURI(),
                jwt,
                errorResponse.getResponseMode());

        assertThat(jwtErrorResponse.getRedirectionURI()).isEqualTo(errorResponse.getRedirectionURI());
        assertThat(jwtErrorResponse.getJWTResponse()).isEqualTo(jwt);
        assertThat(jwtErrorResponse.getResponseMode()).isEqualTo(errorResponse.getResponseMode());

        Map<String, List<String>> params = jwtErrorResponse.toParameters();
        assertThat(MultivaluedMapUtils.getFirstValue(params, "response")).isEqualTo(jwt.serialize());
        assertThat(params.size()).isEqualTo(1);

        URI uri = jwtErrorResponse.toURI();

        assertThat(uri.toString()).startsWith(errorResponse.getRedirectionURI().toString());
        assertThat(uri.getQuery()).isEqualTo("response=" + jwt.serialize());
        assertThat(uri.getFragment()).isNull();

        jwtErrorResponse = AuthenticationResponseParser.parse(uri).toErrorResponse();
        assertThat(jwtErrorResponse.getRedirectionURI()).isEqualTo(errorResponse.getRedirectionURI());
        assertThat(jwtErrorResponse.getJWTResponse().serialize()).isEqualTo(jwt.serialize());
        assertThat(jwtErrorResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);

        // Parse with validator now
        JARMValidator jarmValidator = new JARMValidator(
                new Issuer("https://c2id.com"),
                new ClientID("123"),
                new TestKeySelector(RSA_PUBLIC_KEY));

        AuthenticationErrorResponse validatedResponse = AuthenticationResponseParser.parse(uri, jarmValidator).toErrorResponse();

        assertThat(validatedResponse.getErrorObject()).isEqualTo(errorResponse.getErrorObject());
        assertThat(validatedResponse.getState()).isEqualTo(errorResponse.getState());
    }

    @Test
    public void testJARM_errorLifeCycle_fragment()
            throws Exception {

        AuthenticationErrorResponse errorResponse = new AuthenticationErrorResponse(
                URI.create("https://example.com/cb"),
                OAuth2Error.ACCESS_DENIED,
                new State(),
                ResponseMode.FRAGMENT_JWT);

        JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
                new Issuer("https://c2id.com"),
                new ClientID("123"),
                new Date(),
                errorResponse);

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
        signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));

        JWT jwt = signedJWT;

        AuthenticationErrorResponse jwtErrorResponse = new AuthenticationErrorResponse(
                errorResponse.getRedirectionURI(),
                jwt,
                errorResponse.getResponseMode());

        assertThat(jwtErrorResponse.getRedirectionURI()).isEqualTo(errorResponse.getRedirectionURI());
        assertThat(jwtErrorResponse.getJWTResponse()).isEqualTo(jwt);
        assertThat(jwtErrorResponse.getResponseMode()).isEqualTo(errorResponse.getResponseMode());

        Map<String, List<String>> params = jwtErrorResponse.toParameters();
        assertThat(MultivaluedMapUtils.getFirstValue(params, "response")).isEqualTo(jwt.serialize());
        assertThat(params.size()).isEqualTo(1);

        URI uri = jwtErrorResponse.toURI();

        assertThat(uri.toString()).startsWith(errorResponse.getRedirectionURI().toString());
        assertThat(uri.getQuery()).isNull();
        assertThat(uri.getFragment()).isEqualTo("response=" + jwt.serialize());

        jwtErrorResponse = AuthenticationResponseParser.parse(uri).toErrorResponse();
        assertThat(jwtErrorResponse.getRedirectionURI()).isEqualTo(errorResponse.getRedirectionURI());
        assertThat(jwtErrorResponse.getJWTResponse().serialize()).isEqualTo(jwt.serialize());
        assertThat(jwtErrorResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);

        // Parse with validator now
        JARMValidator jarmValidator = new JARMValidator(
                new Issuer("https://c2id.com"),
                new ClientID("123"),
                new TestKeySelector(RSA_PUBLIC_KEY));

        AuthenticationErrorResponse validatedResponse = AuthenticationResponseParser.parse(uri, jarmValidator).toErrorResponse();

        assertThat(validatedResponse.getErrorObject()).isEqualTo(errorResponse.getErrorObject());
        assertThat(validatedResponse.getState()).isEqualTo(errorResponse.getState());
    }

}
