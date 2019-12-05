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
package be.atbash.ee.openid.connect.sdk.validators;


import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.openid.connect.sdk.Nonce;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.proc.BadJWTException;
import org.junit.Test;

import java.util.Arrays;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the ID token claims verifier.
 */
public class IDTokenClaimsVerifierTest {

    @Test
    public void testHappyMinimalWithNonce()
            throws BadJWTException {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Nonce nonce = new Nonce("xyz");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isEqualTo(nonce);

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(clientID.getValue())
                .expirationTime(exp)
                .issueTime(iat)
                .claim("nonce", nonce.getValue())
                .build();

        verifier.verify(claimsSet);
    }

    @Test
    public void testHappyMinimalWithoutNonce()
            throws BadJWTException {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isNull();

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(clientID.getValue())
                .expirationTime(exp)
                .issueTime(iat)
                .build();

        verifier.verify(claimsSet);
    }

    @Test
    public void testMissingIssuer() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isNull();

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject("alice")
                .audience(clientID.getValue())
                .expirationTime(exp)
                .issueTime(iat)
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Missing JWT issuer (iss) claim");
        }
    }

    @Test
    public void testMissingSubject() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isNull();

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .audience(clientID.getValue())
                .expirationTime(exp)
                .issueTime(iat)
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Missing JWT subject (sub) claim");
        }
    }

    @Test
    public void testMissingAudience() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isNull();

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .expirationTime(exp)
                .issueTime(iat)
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Missing JWT audience (aud) claim");
        }
    }

    @Test
    public void testMissingExpirationTime() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isNull();

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(clientID.getValue())
                .issueTime(iat)
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Missing JWT expiration (exp) claim");
        }
    }

    @Test
    public void testMissingIssueTime() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, null, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isNull();

        Date now = new Date();
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(clientID.getValue())
                .expirationTime(exp)
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Missing JWT issue time (iat) claim");
        }
    }

    @Test
    public void testMissingNonce() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Nonce nonce = new Nonce("xyz");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isEqualTo(nonce);

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(clientID.getValue())
                .expirationTime(exp)
                .issueTime(iat)
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Missing JWT nonce (nonce) claim");
        }
    }

    @Test
    public void testUnexpectedIssuer() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Nonce nonce = new Nonce("xyz");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isEqualTo(nonce);

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://other-issuer.com")
                .subject("alice")
                .audience(clientID.getValue())
                .expirationTime(exp)
                .issueTime(iat)
                .claim("nonce", nonce.getValue())
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Unexpected JWT issuer: https://other-issuer.com");
        }
    }

    @Test
    public void testAudienceMismatch() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Nonce nonce = new Nonce("xyz");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isEqualTo(nonce);

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience("789")
                .expirationTime(exp)
                .issueTime(iat)
                .claim("nonce", nonce.getValue())
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Unexpected JWT audience: [789]");
        }
    }

    @Test
    public void testMultipleAudienceMismatch() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Nonce nonce = new Nonce("xyz");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isEqualTo(nonce);

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(Arrays.asList("456", "789"))
                .expirationTime(exp)
                .issueTime(iat)
                .claim("nonce", nonce.getValue())
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Unexpected JWT audience: [456, 789]");
        }
    }

    @Test
    public void testAzpMismatch() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Nonce nonce = new Nonce("xyz");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isEqualTo(nonce);

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(Arrays.asList(clientID.getValue(), "456"))
                .claim("azp", "456")
                .expirationTime(exp)
                .issueTime(iat)
                .claim("nonce", nonce.getValue())
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Unexpected JWT authorized party (azp) claim: 456");
        }
    }

    @Test
    public void testExpired() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Nonce nonce = new Nonce("xyz");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isEqualTo(nonce);

        Date now = new Date();
        Date oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000L);
        Date twoHoursAgo = new Date(now.getTime() - 2 * 60 * 60 * 1000L);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(clientID.getValue())
                .expirationTime(oneHourAgo)
                .issueTime(twoHoursAgo)
                .claim("nonce", nonce.getValue())
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Expired JWT");
        }
    }

    @Test
    public void testIssueTimeAhead() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Nonce nonce = new Nonce("xyz");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isEqualTo(nonce);

        Date now = new Date();
        Date inOneHour = new Date(now.getTime() + 60 * 60 * 1000L);
        Date inTwoHours = new Date(now.getTime() + 2 * 60 * 60 * 1000L);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(clientID.getValue())
                .expirationTime(inTwoHours)
                .issueTime(inOneHour)
                .claim("nonce", nonce.getValue())
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("JWT issue time ahead of current time");
        }
    }

    @Test
    public void testUnexpectedNonce() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Nonce nonce = new Nonce("xyz");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isEqualTo(nonce);

        Date now = new Date();
        Date iat = new Date(now.getTime() - 5 * 60 * 1000);
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(clientID.getValue())
                .expirationTime(exp)
                .issueTime(iat)
                .claim("nonce", "xxx")
                .build();

        try {
            verifier.verify(claimsSet);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Unexpected JWT nonce (nonce) claim: xxx");
        }
    }

    @Test
    public void testIssuedAtWithPositiveClockSkew()
            throws BadJWTException {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Nonce nonce = new Nonce("xyz");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 60);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isEqualTo(nonce);

        Date now = new Date();
        Date in30Seconds = new Date(now.getTime() + 30 * 1000L);
        Date inOneHour = new Date(now.getTime() + 60 * 60 * 1000L);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(clientID.getValue())
                .expirationTime(inOneHour)
                .issueTime(in30Seconds)
                .claim("nonce", nonce.getValue())
                .build();

        verifier.verify(claimsSet);
    }

    @Test
    public void testExpirationWithNegativeClockSkew()
            throws BadJWTException {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Nonce nonce = new Nonce("xyz");

        IDTokenClaimsVerifier verifier = new IDTokenClaimsVerifier(iss, clientID, nonce, 60);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);
        assertThat(verifier.getExpectedNonce()).isEqualTo(nonce);

        Date now = new Date();
        Date oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000L);
        Date before30Seconds = new Date(now.getTime() - 30 * 1000L);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .subject("alice")
                .audience(clientID.getValue())
                .expirationTime(before30Seconds)
                .issueTime(oneHourAgo)
                .claim("nonce", nonce.getValue())
                .build();

        verifier.verify(claimsSet);
    }
}
