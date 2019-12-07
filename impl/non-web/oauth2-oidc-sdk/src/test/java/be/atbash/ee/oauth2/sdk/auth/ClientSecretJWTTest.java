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
package be.atbash.ee.oauth2.sdk.auth;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.JWTID;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACVerifier;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSObject;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import org.junit.Test;

import java.net.URI;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the client secret JWT authentication class.
 */
public class ClientSecretJWTTest {

    @Test
    public void testSupportedJWAs() {

        Set<JWSAlgorithm> algs = ClientSecretJWT.supportedJWAs();

        assertThat(algs).contains(JWSAlgorithm.HS256);
        assertThat(algs).contains(JWSAlgorithm.HS384);
        assertThat(algs).contains(JWSAlgorithm.HS512);
        assertThat(algs).hasSize(3);
    }

    @Test
    public void testRun()
            throws Exception {

        ClientID clientID = new ClientID("http://client.com");
        Audience audience = new Audience("http://idp.com");
        Date exp = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000 + 3600);
        Date nbf = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000);
        Date iat = DateUtils.fromSecondsSinceEpoch(new Date().getTime() / 1000);
        JWTID jti = new JWTID();

        JWTAuthenticationClaimsSet assertion = new JWTAuthenticationClaimsSet(clientID, audience.toSingleAudienceList(), exp, nbf, iat, jti);


        JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS256);

        SignedJWT jwt = new SignedJWT(jwsHeader, assertion.toJWTClaimsSet());

        Secret secret = new Secret();

        MACSigner signer = new MACSigner(secret.getValueBytes());

        jwt.sign(signer);

        ClientSecretJWT clientSecretJWT = new ClientSecretJWT(jwt);

        Map<String, List<String>> params = clientSecretJWT.toParameters();
        params.put("client_id", Collections.singletonList(clientID.getValue())); // add optional client_id to test parser

        clientSecretJWT = ClientSecretJWT.parse(params);

        assertThat(clientSecretJWT.getClientID().getValue()).isEqualTo("http://client.com");

        jwt = clientSecretJWT.getClientAssertion();

        assertThat(jwt.getState().equals(JWSObject.State.SIGNED)).isTrue();

        MACVerifier verifier = new MACVerifier(secret.getValueBytes());

        boolean verified = jwt.verify(verifier);

        assertThat(verified).isTrue();

        assertion = clientSecretJWT.getJWTAuthenticationClaimsSet();

        assertThat(assertion.getClientID().getValue()).isEqualTo(clientID.getValue());
        assertThat(assertion.getIssuer().getValue()).isEqualTo(clientID.getValue());
        assertThat(assertion.getSubject().getValue()).isEqualTo(clientID.getValue());
        assertThat(assertion.getAudience().get(0).getValue()).isEqualTo(audience.getValue());
        assertThat(assertion.getExpirationTime().getTime()).isEqualTo(exp.getTime());
        assertThat(assertion.getNotBeforeTime().getTime()).isEqualTo(nbf.getTime());
        assertThat(assertion.getIssueTime().getTime()).isEqualTo(iat.getTime());
        assertThat(assertion.getJWTID().getValue()).isEqualTo(jti.getValue());
    }

    @Test
    public void testWithJWTHelper()
            throws Exception {

        ClientID clientID = new ClientID("123");
        URI tokenEndpoint = new URI("https://c2id.com/token");
        Secret secret = new Secret(256 / 8); // generate 256 bit secret

        ClientSecretJWT clientSecretJWT = new ClientSecretJWT(clientID, tokenEndpoint, JWSAlgorithm.HS256, secret);

        clientSecretJWT = ClientSecretJWT.parse(clientSecretJWT.toParameters());

        assertThat(clientSecretJWT.getClientAssertion().verify(new MACVerifier(secret.getValueBytes()))).isTrue();

        assertThat(clientSecretJWT.getJWTAuthenticationClaimsSet().getClientID()).isEqualTo(clientID);
        assertThat(clientSecretJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue()).isEqualTo(clientID.getValue());
        assertThat(clientSecretJWT.getJWTAuthenticationClaimsSet().getSubject().getValue()).isEqualTo(clientID.getValue());
        assertThat(clientSecretJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue()).isEqualTo(tokenEndpoint.toString());

        // 4 min < exp < 6 min
        long now = new Date().getTime();
        Date fourMinutesFromNow = new Date(now + 4 * 60 * 1000L);
        Date sixMinutesFromNow = new Date(now + 6 * 60 * 1000L);
        assertThat(clientSecretJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(fourMinutesFromNow)).isTrue();
        assertThat(clientSecretJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(sixMinutesFromNow)).isTrue();
        assertThat(clientSecretJWT.getJWTAuthenticationClaimsSet().getJWTID()).isNotNull();
        assertThat(clientSecretJWT.getJWTAuthenticationClaimsSet().getIssueTime()).isNull();
        assertThat(clientSecretJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime()).isNull();
    }

    @Test
    public void testParse_clientIDMismatch()
            throws Exception {

        ClientID clientID = new ClientID("123");
        URI tokenEndpoint = new URI("https://c2id.com/token");
        Secret secret = new Secret(256 / 8); // generate 256 bit secret

        ClientSecretJWT clientSecretJWT = new ClientSecretJWT(clientID, tokenEndpoint, JWSAlgorithm.HS256, secret);

        Map<String, List<String>> params = clientSecretJWT.toParameters();

        assertThat(params.get("client_id")).isNull();

        params.put("client_id", Collections.singletonList("456")); // different client_id

        try {
            ClientSecretJWT.parse(params);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Invalid client secret JWT authentication: The client identifier doesn't match the client assertion subject / issuer");
        }

    }
}
