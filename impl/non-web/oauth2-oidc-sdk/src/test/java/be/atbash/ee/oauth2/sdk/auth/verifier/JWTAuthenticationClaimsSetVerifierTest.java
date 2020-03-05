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
package be.atbash.ee.oauth2.sdk.auth.verifier;


import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.proc.BadJWTException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the JWT claims set verifier for client authentication assertions.
 */
public class JWTAuthenticationClaimsSetVerifierTest {


    // Create for simple Authorisation Server (AS)
    private static JWTAuthenticationClaimsSetVerifier createForAS() {

        URI tokenEndpoint = URI.create("https://c2id.com/token");

        Set<Audience> expectedAud = new LinkedHashSet<>();
        expectedAud.add(new Audience(tokenEndpoint.toString()));

        return new JWTAuthenticationClaimsSetVerifier(expectedAud);
    }


    // Create for OpenID provider
    private static JWTAuthenticationClaimsSetVerifier createForOP() {

        URI tokenEndpoint = URI.create("https://c2id.com/token");
        URI opIssuer = URI.create("https://c2id.com");

        Set<Audience> expectedAud = new LinkedHashSet<>();
        expectedAud.add(new Audience(tokenEndpoint.toString()));
        expectedAud.add(new Audience(opIssuer.toString()));

        return new JWTAuthenticationClaimsSetVerifier(expectedAud);
    }


    private static void ensureRejected(JWTClaimsSet claimsSet,
                                       String expectedMessage) {

        BadJWTException exception = Assertions.assertThrows(BadJWTException.class, () -> createForAS().verify(claimsSet));

        assertThat(exception.getMessage()).isEqualTo(expectedMessage);

        BadJWTException exception1 = Assertions.assertThrows(BadJWTException.class, () -> createForOP().verify(claimsSet));
        assertThat(exception1.getMessage()).isEqualTo(expectedMessage);

    }

    @Test
    public void testAudForAS() {

        JWTAuthenticationClaimsSetVerifier verifier = createForAS();

        assertThat(verifier.getExpectedAudience()).contains(new Audience("https://c2id.com/token"));
        assertThat(verifier.getExpectedAudience()).hasSize(1);
    }

    @Test
    public void testAudForOP() {

        JWTAuthenticationClaimsSetVerifier verifier = createForAS();

        assertThat(verifier.getExpectedAudience()).contains(new Audience("https://c2id.com/token"));
        assertThat(verifier.getExpectedAudience()).hasSize(1);
    }

    @Test
    public void testHappy()
            throws BadJWTException {

        Date now = new Date();
        Date in5min = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(in5min)
                .audience("https://c2id.com/token")
                .issuer("123")
                .subject("123")
                .build();

        createForAS().verify(claimsSet);
        createForOP().verify(claimsSet);
    }

    @Test
    public void testExpired() {

        Date now = new Date();
        Date before5min = new Date(now.getTime() - 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(before5min)
                .audience("https://c2id.com")
                .issuer("123")
                .subject("123")
                .build();

        ensureRejected(claimsSet, "Expired JWT");
    }

    @Test
    public void testMissingExpiration() {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience("https://c2id.com")
                .issuer("123")
                .subject("123")
                .build();

        ensureRejected(claimsSet, "Missing JWT expiration claim");
    }

    @Test
    public void testMissingAud() {

        Date now = new Date();
        Date in5min = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(in5min)
                .issuer("123")
                .subject("123")
                .build();

        ensureRejected(claimsSet, "Missing JWT audience claim");
    }

    @Test
    public void testUnexpectedAud() {

        Date now = new Date();
        Date in5min = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(in5min)
                .audience("c2id.com")
                .issuer("123")
                .subject("123")
                .build();

        BadJWTException exception = Assertions.assertThrows(BadJWTException.class, () -> createForAS().verify(claimsSet));
        assertThat(exception.getMessage()).isEqualTo("Invalid JWT audience claim, expected [https://c2id.com/token]");

        BadJWTException exception1 = Assertions.assertThrows(BadJWTException.class, () -> createForOP().verify(claimsSet));
        assertThat(exception1.getMessage()).isEqualTo("Invalid JWT audience claim, expected [https://c2id.com/token, https://c2id.com]");

    }

    @Test
    public void testMissingIssuer()
            throws BadJWTException {

        Date now = new Date();
        Date in5min = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(in5min)
                .audience("https://c2id.com/token")
                .subject("123")
                .build();

        ensureRejected(claimsSet, "Missing JWT issuer claim");
    }

    @Test
    public void testMissingSubject()
            throws BadJWTException {

        Date now = new Date();
        Date in5min = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(in5min)
                .audience("https://c2id.com/token")
                .issuer("123")
                .build();

        ensureRejected(claimsSet, "Missing JWT subject claim");
    }

    @Test
    public void testIssuerSubjectMismatch() {

        Date now = new Date();
        Date in5min = new Date(now.getTime() + 5 * 60 * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .expirationTime(in5min)
                .audience("https://c2id.com/token")
                .issuer("123")
                .subject("456")
                .build();

        ensureRejected(claimsSet, "Issuer and subject JWT claims don't match");
    }
}
