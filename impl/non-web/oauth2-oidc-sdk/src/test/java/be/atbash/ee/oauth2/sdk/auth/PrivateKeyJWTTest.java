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
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.ECDSAVerifier;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSAVerifier;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the private key JWT authentication class.
 */
public class PrivateKeyJWTTest {

    @Test
    public void testSupportedJWAs() {

        Set<JWSAlgorithm> algs = PrivateKeyJWT.supportedJWAs();

        assertThat(algs).contains(JWSAlgorithm.RS256);
        assertThat(algs).contains(JWSAlgorithm.RS384);
        assertThat(algs).contains(JWSAlgorithm.RS512);
        assertThat(algs).contains(JWSAlgorithm.PS256);
        assertThat(algs).contains(JWSAlgorithm.PS384);
        assertThat(algs).contains(JWSAlgorithm.PS512);
        assertThat(algs).contains(JWSAlgorithm.ES256);
        assertThat(algs).contains(JWSAlgorithm.ES256K);
        assertThat(algs).contains(JWSAlgorithm.ES384);
        assertThat(algs).contains(JWSAlgorithm.ES512);
        assertThat(algs).hasSize(10);
    }

    @Test
    public void testWithRS256()
            throws Exception {

        ClientID clientID = new ClientID("123");
        URI tokenEndpoint = new URI("https://c2id.com/token");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = keyGen.generateKeyPair();
        RSAPrivateKey priv = (RSAPrivateKey) pair.getPrivate();
        RSAPublicKey pub = (RSAPublicKey) pair.getPublic();

        PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, tokenEndpoint, JWSAlgorithm.RS256, priv, null, null);

        privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());

        assertThat(privateKeyJWT.getClientAssertion().verify(new RSASSAVerifier(pub))).isTrue();

        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID()).isEqualTo(clientID);
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue()).isEqualTo(clientID.getValue());
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue()).isEqualTo(clientID.getValue());
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue()).isEqualTo(tokenEndpoint.toString());

        // 4 min < exp < 6 min
        final long now = new Date().getTime();
        final Date fourMinutesFromNow = new Date(now + 4 * 60 * 1000L);
        final Date sixMinutesFromNow = new Date(now + 6 * 60 * 1000L);
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(fourMinutesFromNow)).isTrue();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(sixMinutesFromNow)).isTrue();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID()).isNotNull();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime()).isNull();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime()).isNull();
    }

    @Test
    public void testWithRS256AndKeyID()
            throws Exception {

        ClientID clientID = new ClientID("123");
        URI tokenEndpoint = new URI("https://c2id.com/token");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = keyGen.generateKeyPair();
        RSAPrivateKey priv = (RSAPrivateKey) pair.getPrivate();
        RSAPublicKey pub = (RSAPublicKey) pair.getPublic();

        PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, tokenEndpoint, JWSAlgorithm.RS256, priv, "1", null);
        assertThat(privateKeyJWT.getClientAssertion().getHeader().getKeyID()).isEqualTo("1");

        privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());

        assertThat(privateKeyJWT.getClientAssertion().getHeader().getKeyID()).isEqualTo("1");

        assertThat(privateKeyJWT.getClientAssertion().verify(new RSASSAVerifier(pub))).isTrue();

        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID()).isEqualTo(clientID);
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue()).isEqualTo(clientID.getValue());
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue()).isEqualTo(clientID.getValue());
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue()).isEqualTo(tokenEndpoint.toString());

        // 4 min < exp < 6 min
        final long now = new Date().getTime();
        final Date fourMinutesFromNow = new Date(now + 4 * 60 * 1000L);
        final Date sixMinutesFromNow = new Date(now + 6 * 60 * 1000L);
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(fourMinutesFromNow)).isTrue();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(sixMinutesFromNow)).isTrue();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID()).isNotNull();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime()).isNull();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime()).isNull();
    }

    @Test
    public void testWithES256()
            throws Exception {

        ClientID clientID = new ClientID("123");
        URI tokenEndpoint = new URI("https://c2id.com/token");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        KeyPair pair = keyGen.generateKeyPair();
        ECPrivateKey priv = (ECPrivateKey) pair.getPrivate();
        ECPublicKey pub = (ECPublicKey) pair.getPublic();

        PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, tokenEndpoint, JWSAlgorithm.ES256, priv, null, null);

        privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());

        assertThat(privateKeyJWT.getClientAssertion().verify(new ECDSAVerifier(pub))).isTrue();

        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID()).isEqualTo(clientID);
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue()).isEqualTo(clientID.getValue());
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue()).isEqualTo(clientID.getValue());
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue()).isEqualTo(tokenEndpoint.toString());

        // 4 min < exp < 6 min
        final long now = new Date().getTime();
        final Date fourMinutesFromNow = new Date(now + 4 * 60 * 1000L);
        final Date sixMinutesFromNow = new Date(now + 6 * 60 * 1000L);
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(fourMinutesFromNow)).isTrue();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(sixMinutesFromNow)).isTrue();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID()).isNotNull();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime()).isNull();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime()).isNull();
    }

    @Test
    public void testWithES256AndKeyID()
            throws Exception {

        ClientID clientID = new ClientID("123");
        URI tokenEndpoint = new URI("https://c2id.com/token");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        KeyPair pair = keyGen.generateKeyPair();
        ECPrivateKey priv = (ECPrivateKey) pair.getPrivate();
        ECPublicKey pub = (ECPublicKey) pair.getPublic();

        PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, tokenEndpoint, JWSAlgorithm.ES256, priv, "1", null);
        assertThat(privateKeyJWT.getClientAssertion().getHeader().getKeyID()).isEqualTo("1");

        privateKeyJWT = PrivateKeyJWT.parse(privateKeyJWT.toParameters());

        assertThat(privateKeyJWT.getClientAssertion().getHeader().getKeyID()).isEqualTo("1");

        assertThat(privateKeyJWT.getClientAssertion().verify(new ECDSAVerifier(pub))).isTrue();

        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getClientID()).isEqualTo(clientID);
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssuer().getValue()).isEqualTo(clientID.getValue());
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getSubject().getValue()).isEqualTo(clientID.getValue());
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getAudience().get(0).getValue()).isEqualTo(tokenEndpoint.toString());

        // 4 min < exp < 6 min
        final long now = new Date().getTime();
        final Date fourMinutesFromNow = new Date(now + 4 * 60 * 1000L);
        final Date sixMinutesFromNow = new Date(now + 6 * 60 * 1000L);
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().after(fourMinutesFromNow)).isTrue();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getExpirationTime().before(sixMinutesFromNow)).isTrue();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getJWTID()).isNotNull();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getIssueTime()).isNull();
        assertThat(privateKeyJWT.getJWTAuthenticationClaimsSet().getNotBeforeTime()).isNull();
    }

    @Test
    public void testParse_clientIDMismatch()
            throws Exception {

        ClientID clientID = new ClientID("123");
        URI tokenEndpoint = new URI("https://c2id.com/token");

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = keyGen.generateKeyPair();
        RSAPrivateKey priv = (RSAPrivateKey) pair.getPrivate();
        RSAPublicKey pub = (RSAPublicKey) pair.getPublic();

        PrivateKeyJWT privateKeyJWT = new PrivateKeyJWT(clientID, tokenEndpoint, JWSAlgorithm.RS256, priv, null, null);

        Map<String, List<String>> params = privateKeyJWT.toParameters();

        assertThat(params.get("client_id")).isNull();

        params.put("client_id", Collections.singletonList("456")); // different client_id

        try {
            PrivateKeyJWT.parse(params);
            fail();
        } catch (OAuth2JSONParseException e) {
            assertThat(e.getMessage()).isEqualTo("Invalid private key JWT authentication: The client identifier doesn't match the client assertion subject / issuer");
        }

    }
}
