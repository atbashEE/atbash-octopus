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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.SerializeException;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.oauth2.sdk.util.URLUtils;
import be.atbash.ee.openid.connect.sdk.claims.IDTokenClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jose.Algorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.PlainJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.Test;

import java.net.URI;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the logout request class.
 */
public class LogoutRequestTest {


    private static JWT createIDTokenHint()
            throws OAuth2JSONParseException {

        Issuer iss = new Issuer("https://c2id.com");
        Subject sub = new Subject("alice");
        List<Audience> audList = new Audience("123").toSingleAudienceList();
        Date exp = new Date(2000L);
        Date iat = new Date(1000L);

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

        return new PlainJWT(claimsSet.toJWTClaimsSet());
    }

    @Test
    public void testMinimal()
            throws Exception {

        URI endpoint = URI.create("https://c2id.com/logout");
        LogoutRequest logoutRequest = new LogoutRequest(endpoint);
        assertThat(logoutRequest.getIDTokenHint()).isNull();
        assertThat(logoutRequest.getPostLogoutRedirectionURI()).isNull();
        assertThat(logoutRequest.getState()).isNull();
        assertThat(logoutRequest.getEndpointURI()).isEqualTo(endpoint);

        String query = logoutRequest.toQueryString();
        assertThat(query).isEqualTo("");

        URI request = logoutRequest.toURI();
        assertThat(request.toString()).isEqualTo("https://c2id.com/logout");
    }

    @Test
    public void testWithIDTokenHint()
            throws Exception {

        JWT idToken = createIDTokenHint();

        URI endpoint = new URI("https://c2id.com/logout");

        LogoutRequest request = new LogoutRequest(endpoint, idToken);

        assertThat(request.getEndpointURI()).isEqualTo(endpoint);
        assertThat(request.getIDTokenHint()).isEqualTo(idToken);
        assertThat(request.getPostLogoutRedirectionURI()).isNull();
        assertThat(request.getState()).isNull();

        assertThat(request.toURI().toString()).isEqualTo(endpoint + "?id_token_hint=" + idToken.serialize());

        HTTPRequest httpRequest = request.toHTTPRequest();
        assertThat(httpRequest.getMethod()).isEqualTo(HTTPRequest.Method.GET);

        request = LogoutRequest.parse(httpRequest);

        assertThat(request.getIDTokenHint().getHeader().getAlgorithm()).isEqualTo(Algorithm.NONE);
        assertThat(request.getIDTokenHint().getJWTClaimsSet().getIssuer()).isEqualTo(idToken.getJWTClaimsSet().getIssuer());
        assertThat(request.getIDTokenHint().getJWTClaimsSet().getSubject()).isEqualTo(idToken.getJWTClaimsSet().getSubject());
        assertThat(request.getIDTokenHint().getJWTClaimsSet().getAudience().get(0)).isEqualTo(idToken.getJWTClaimsSet().getAudience().get(0));
        assertThat(request.getIDTokenHint().getJWTClaimsSet().getExpirationTime()).isEqualTo(idToken.getJWTClaimsSet().getExpirationTime());
        assertThat(request.getIDTokenHint().getJWTClaimsSet().getIssueTime()).isEqualTo(idToken.getJWTClaimsSet().getIssueTime());
        assertThat(request.getPostLogoutRedirectionURI()).isNull();
        assertThat(request.getState()).isNull();
    }

    @Test
    public void testFullConstructor()
            throws Exception {

        JWT idToken = createIDTokenHint();

        URI postLogoutRedirectURI = new URI("https://client.com/post-logout");
        State state = new State();

        URI endpoint = new URI("https://c2id.com/logout");

        LogoutRequest request = new LogoutRequest(endpoint, idToken, postLogoutRedirectURI, state);

        assertThat(request.getEndpointURI()).isEqualTo(endpoint);
        assertThat(request.getIDTokenHint()).isEqualTo(idToken);
        assertThat(request.getPostLogoutRedirectionURI()).isEqualTo(postLogoutRedirectURI);
        assertThat(request.getState()).isEqualTo(state);

        Map<String, List<String>> params = request.toParameters();
        assertThat(params.get("id_token_hint")).isEqualTo(Collections.singletonList(idToken.serialize()));
        assertThat(params.get("post_logout_redirect_uri")).isEqualTo(Collections.singletonList(postLogoutRedirectURI.toString()));
        assertThat(params.get("state")).isEqualTo(Collections.singletonList(state.getValue()));
        assertThat(params).hasSize(3);

        URI outputURI = request.toURI();

        assertThat(outputURI.toString().startsWith("https://c2id.com/logout")).isTrue();
        params = URLUtils.parseParameters(outputURI.getQuery());
        assertThat(params.get("id_token_hint")).isEqualTo(Collections.singletonList(idToken.serialize()));
        assertThat(params.get("post_logout_redirect_uri")).isEqualTo(Collections.singletonList(postLogoutRedirectURI.toString()));
        assertThat(params.get("state")).isEqualTo(Collections.singletonList(state.getValue()));
        assertThat(params).hasSize(3);

        request = LogoutRequest.parse(outputURI);

        assertThat(request.getEndpointURI()).isEqualTo(endpoint);
        assertThat(request.getIDTokenHint().serialize()).isEqualTo(idToken.serialize());
        assertThat(request.getPostLogoutRedirectionURI()).isEqualTo(postLogoutRedirectURI);
        assertThat(request.getState()).isEqualTo(state);
    }

    @Test
    public void testRejectUnsignedIDToken()
            throws Exception {

        Issuer iss = new Issuer("https://c2id.com");
        Subject sub = new Subject("alice");
        List<Audience> audList = new Audience("123").toSingleAudienceList();
        Date exp = new Date(2000L);
        Date iat = new Date(1000L);

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(iss, sub, audList, exp, iat);

        SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet.toJWTClaimsSet());

        URI postLogoutRedirectURI = new URI("https://client.com/post-logout");

        URI endpoint = new URI("https://c2id.com/logout");

        try {
            new LogoutRequest(endpoint, idToken, postLogoutRedirectURI, null).toQueryString();
            fail();
        } catch (SerializeException e) {
            // ok
        }
    }

    @Test
    public void testRejectStateWithoutRedirectionURI()
            throws Exception {

        JWT idToken = createIDTokenHint();

        URI endpoint = new URI("https://c2id.com/logout");

        try {
            new LogoutRequest(endpoint, idToken, null, new State());
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The state parameter required a post-logout redirection URI");
        }
    }


    // See https://bitbucket.org/connect2id/oauth-2.0-sdk-with-openid-connect-extensions/issues/147/authorizationrequestparse-final-uri-uri
    @Test
    public void testParseWithEncodedEqualsChar()
            throws Exception {

        JWT idToken = createIDTokenHint();

        URI postLogoutRedirectURI = URI.create("https://client.com/post-logout?app=123");

        String encodedPostLogoutRedirectURI = URLEncoder.encode(postLogoutRedirectURI.toString(), "UTF-8");

        URI requestURI = URI.create("https://server.example.com/logout?" +
                "id_token_hint=" + idToken.serialize() +
                "&post_logout_redirect_uri=" + encodedPostLogoutRedirectURI);

        LogoutRequest request = LogoutRequest.parse(requestURI);

        assertThat(request.getPostLogoutRedirectionURI()).isEqualTo(postLogoutRedirectURI);
        assertThat(request.getState()).isNull();
        assertThat(request.getIDTokenHint()).isNotNull();
        assertThat(request.getEndpointURI().toString()).isEqualTo("https://server.example.com/logout");
    }

    @Test
    public void testNullParseNullQueryString()
            throws Exception {

        LogoutRequest request = LogoutRequest.parse((String) null);
        assertThat(request.getIDTokenHint()).isNull();
        assertThat(request.getPostLogoutRedirectionURI()).isNull();
        assertThat(request.getState()).isNull();

        request = LogoutRequest.parse((URI) null, (String) null);
        assertThat(request.getIDTokenHint()).isNull();
        assertThat(request.getPostLogoutRedirectionURI()).isNull();
        assertThat(request.getState()).isNull();
    }
}
