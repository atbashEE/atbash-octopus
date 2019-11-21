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


import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import org.junit.Test;

import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the authorisation response class.
 */
public class AuthorizationResponseTest {


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


    // See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
    @Test
    public void testParseWithEncodedEqualsChar()
            throws Exception {

        URI redirectURI = URI.create("https://example.com/in");

        AuthorizationCode code = new AuthorizationCode("===code===");
        State state = new State("===state===");

        AuthorizationResponse response = new AuthorizationSuccessResponse(redirectURI, code, null, state, ResponseMode.QUERY);

        URI uri = response.toURI();

        response = AuthorizationResponse.parse(uri);

        assertThat(response.getState()).isEqualTo(state);

        AuthorizationSuccessResponse successResponse = (AuthorizationSuccessResponse) response;

        assertThat(successResponse.getAuthorizationCode()).isEqualTo(code);
        assertThat(successResponse.getAccessToken()).isNull();
    }

    @Test
    public void testToSuccessResponse()
            throws Exception {

        AuthorizationCode code = new AuthorizationCode();
        State state = new State();
        AuthorizationSuccessResponse successResponse = new AuthorizationSuccessResponse(URI.create("https://example.com/in"), code, null, state, ResponseMode.QUERY);

        URI uri = successResponse.toURI();

        successResponse = AuthorizationResponse.parse(uri).toSuccessResponse();

        assertThat(successResponse.getAuthorizationCode()).isEqualTo(code);
        assertThat(successResponse.getState()).isEqualTo(state);
    }

    @Test
    public void testToErrorResponse()
            throws Exception {

        State state = new State();

        AuthorizationErrorResponse errorResponse = new AuthorizationErrorResponse(URI.create("https://example.com/in"), OAuth2Error.ACCESS_DENIED, state, ResponseMode.QUERY);

        URI uri = errorResponse.toURI();

        errorResponse = AuthorizationResponse.parse(uri).toErrorResponse();

        assertThat(errorResponse.getErrorObject()).isEqualTo(OAuth2Error.ACCESS_DENIED);
        assertThat(errorResponse.getState()).isEqualTo(state);
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

        AuthorizationResponse response = AuthorizationResponse.parse(uri);

        AuthorizationSuccessResponse successResponse = response.toSuccessResponse();
        assertThat(successResponse.getAuthorizationCode()).isNull();
        assertThat(successResponse.getAccessToken()).isNull();
        assertThat(successResponse.getState()).isNull();
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

        AuthorizationResponse response = AuthorizationResponse.parse(uri);

        AuthorizationSuccessResponse successResponse = response.toSuccessResponse();
        assertThat(successResponse.getAuthorizationCode()).isNull();
        assertThat(successResponse.getAccessToken()).isNull();
        assertThat(successResponse.getState()).isNull();
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

        AuthorizationResponse response = AuthorizationResponse.parse(httpRequest);

        AuthorizationSuccessResponse successResponse = response.toSuccessResponse();
        assertThat(successResponse.getAuthorizationCode()).isNull();
        assertThat(successResponse.getAccessToken()).isNull();
        assertThat(successResponse.getState()).isNull();
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

	/*
	@Test
	public void testJARM_successLifeCycle_query()
		throws Exception {
		
		AuthorizationSuccessResponse successResponse = new AuthorizationSuccessResponse(
			URI.create("https://example.com/cb"),
			new AuthorizationCode(),
			null,
			new State(),
			ResponseMode.QUERY_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			successResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		JWT jwt = signedJWT;
		
		AuthorizationSuccessResponse jwtSuccessResponse = new AuthorizationSuccessResponse(
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
		
		assertThat(uri.toString().startsWith(successResponse.getRedirectionURI().toString())).isTrue();
		assertThat(uri.getQuery()).isEqualTo("response=" + jwt.serialize());
		assertThat(uri.getFragment()).isNull();
		
		jwtSuccessResponse = AuthorizationResponse.parse(uri).toSuccessResponse();
		assertThat(jwtSuccessResponse.getRedirectionURI()).isEqualTo(successResponse.getRedirectionURI());
		assertThat(jwtSuccessResponse.getJWTResponse().serialize()).isEqualTo(jwt.serialize());
		assertThat(jwtSuccessResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);
		
		// Parse with validator now
		JARMValidator jarmValidator = new JARMValidator(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			JWSAlgorithm.RS256,
			new JWKSet(new RSAKey.Builder(RSA_PUBLIC_KEY).build()));
		
		AuthorizationSuccessResponse validatedResponse = AuthorizationResponse.parse(uri, jarmValidator).toSuccessResponse();
		
		assertThat(validatedResponse.getAuthorizationCode()).isEqualTo(successResponse.getAuthorizationCode());
		assertThat(validatedResponse.getState()).isEqualTo(successResponse.getState());
	}

	@Test
	public void testJARM_successLifeCycle_fragment()
		throws Exception {
		
		AuthorizationSuccessResponse successResponse = new AuthorizationSuccessResponse(
			URI.create("https://example.com/cb"),
			null,
			new BearerAccessToken(),
			new State(),
			ResponseMode.FRAGMENT_JWT);
		
		JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			new Date(),
			successResponse);
		
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
		signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));
		
		JWT jwt = signedJWT;
		
		AuthorizationSuccessResponse jwtSuccessResponse = new AuthorizationSuccessResponse(
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
		
		assertThat(uri.toString().startsWith(successResponse.getRedirectionURI().toString())).isTrue();
		assertThat(uri.getQuery()).isNull();
		assertThat(uri.getFragment()).isEqualTo("response=" + jwt.serialize());
		
		jwtSuccessResponse = AuthorizationResponse.parse(uri).toSuccessResponse();
		assertThat(jwtSuccessResponse.getRedirectionURI()).isEqualTo(successResponse.getRedirectionURI());
		assertThat(jwtSuccessResponse.getJWTResponse().serialize()).isEqualTo(jwt.serialize());
		assertThat(jwtSuccessResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);
		
		// Parse with validator now
		JARMValidator jarmValidator = new JARMValidator(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			JWSAlgorithm.RS256,
			new JWKSet(new RSAKey.Builder(RSA_PUBLIC_KEY).build()));
		
		AuthorizationSuccessResponse validatedResponse = AuthorizationResponse.parse(uri, jarmValidator).toSuccessResponse();
		
		assertThat(validatedResponse.getAccessToken()).isEqualTo(successResponse.getAccessToken());
		assertThat(validatedResponse.getState()).isEqualTo(successResponse.getState());
	}

	@Test
	public void testJARM_errorLifeCycle_query()
		throws Exception {
		
		AuthorizationErrorResponse errorResponse = new AuthorizationErrorResponse(
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
		
		AuthorizationErrorResponse jwtErrorResponse = new AuthorizationErrorResponse(
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
		
		assertThat(uri.toString().startsWith(errorResponse.getRedirectionURI().toString())).isTrue();
		assertThat(uri.getQuery()).isEqualTo("response=" + jwt.serialize());
		assertThat(uri.getFragment()).isNull();
		
		jwtErrorResponse = AuthorizationResponse.parse(uri).toErrorResponse();
		assertThat(jwtErrorResponse.getRedirectionURI()).isEqualTo(errorResponse.getRedirectionURI());
		assertThat(jwtErrorResponse.getJWTResponse().serialize()).isEqualTo(jwt.serialize());
		assertThat(jwtErrorResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);
		
		// Parse with validator now
		JARMValidator jarmValidator = new JARMValidator(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			JWSAlgorithm.RS256,
			new JWKSet(new RSAKey.Builder(RSA_PUBLIC_KEY).build()));
		
		AuthorizationErrorResponse validatedResponse = AuthorizationResponse.parse(uri, jarmValidator).toErrorResponse();
		
		assertThat(validatedResponse.getErrorObject()).isEqualTo(errorResponse.getErrorObject());
		assertThat(validatedResponse.getState()).isEqualTo(errorResponse.getState());
	}


	@Test
	public void testJARM_errorLifeCycle_fragment()
		throws Exception {
		
		AuthorizationErrorResponse errorResponse = new AuthorizationErrorResponse(
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
		
		AuthorizationErrorResponse jwtErrorResponse = new AuthorizationErrorResponse(
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
		
		assertThat(uri.toString().startsWith(errorResponse.getRedirectionURI().toString())).isTrue();
		assertThat(uri.getQuery()).isNull();
		assertThat(uri.getFragment()).isEqualTo("response=" + jwt.serialize());
		
		jwtErrorResponse = AuthorizationResponse.parse(uri).toErrorResponse();
		assertThat(jwtErrorResponse.getRedirectionURI()).isEqualTo(errorResponse.getRedirectionURI());
		assertThat(jwtErrorResponse.getJWTResponse().serialize()).isEqualTo(jwt.serialize());
		assertThat(jwtErrorResponse.getResponseMode()).isEqualTo(ResponseMode.JWT);
		
		// Parse with validator now
		JARMValidator jarmValidator = new JARMValidator(
			new Issuer("https://c2id.com"),
			new ClientID("123"),
			JWSAlgorithm.RS256,
			new JWKSet(new RSAKey.Builder(RSA_PUBLIC_KEY).build()));
		
		AuthorizationErrorResponse validatedResponse = AuthorizationResponse.parse(uri, jarmValidator).toErrorResponse();
		
		assertThat(validatedResponse.getErrorObject()).isEqualTo(errorResponse.getErrorObject());
		assertThat(validatedResponse.getState()).isEqualTo(errorResponse.getState());
	}

	 */
}
