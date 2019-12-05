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
package be.atbash.ee.oauth2.sdk.jarm;

import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import org.junit.After;
import org.junit.Test;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.util.Arrays;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class JARMClaimsVerifierTest {

    private TestLogger logger = TestLoggerFactory.getTestLogger(JARMClaimsVerifier.class);


    @After
    public void teardown() {
        TestLoggerFactory.clear();
    }

    @Test
    public void testHappyMinimal() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);

        Date now = new Date();
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .audience(clientID.getValue())
                .expirationTime(exp)
                .build();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void testMissingIssuer() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);

        Date now = new Date();
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(clientID.getValue())
                .expirationTime(exp)
                .build();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Missing JWT issuer (iss) claim");
    }

    @Test
    public void testMissingAudience() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);

        Date now = new Date();
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .expirationTime(exp)
                .build();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Missing JWT audience (aud) claim");
    }

    @Test
    public void testMissingExpirationTime() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .audience(clientID.getValue())
                .build();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Missing JWT expiration (exp) claim");
    }

    @Test
    public void testUnexpectedIssuer() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);

        Date now = new Date();
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://other-issuer.com")
                .audience(clientID.getValue())
                .expirationTime(exp)
                .build();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Unexpected JWT issuer: https://other-issuer.com");
    }

    @Test
    public void testAudienceMismatch() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);

        Date now = new Date();
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .audience("789")
                .expirationTime(exp)
                .build();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();


        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Unexpected JWT audience: [789]");
    }

    @Test
    public void testMultipleAudienceMismatch() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);

        Date now = new Date();
        Date exp = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .audience(Arrays.asList("456", "789"))
                .expirationTime(exp)
                .build();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Unexpected JWT audience: [456, 789]");
    }

    @Test
    public void testExpired() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 0);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);

        Date now = new Date();
        Date oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000L);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .audience(clientID.getValue())
                .expirationTime(oneHourAgo)
                .build();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isFalse();


        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Expired JWT");

    }

    @Test
    public void testIssuedAtWithPositiveClockSkew() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 60);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);

        Date now = new Date();
        Date in30Seconds = new Date(now.getTime() + 30 * 1000L);
        Date inOneHour = new Date(now.getTime() + 60 * 60 * 1000L);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .audience(clientID.getValue())
                .expirationTime(inOneHour)
                .issueTime(in30Seconds)
                .build();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();
    }

    @Test
    public void testExpirationWithNegativeClockSkew() {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        JARMClaimsVerifier verifier = new JARMClaimsVerifier(iss, clientID, 60);

        assertThat(verifier.getExpectedIssuer()).isEqualTo(iss);
        assertThat(verifier.getClientID()).isEqualTo(clientID);

        Date now = new Date();
        Date oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000L);
        Date before30Seconds = new Date(now.getTime() - 30 * 1000L);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(iss.getValue())
                .audience(clientID.getValue())
                .expirationTime(before30Seconds)
                .issueTime(oneHourAgo)
                .build();

        boolean valid = verifier.verify(null, claimsSet);
        assertThat(valid).isTrue();
        assertThat(logger.getLoggingEvents()).isEmpty();
    }
}