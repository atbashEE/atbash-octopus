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
package be.atbash.ee.oauth2.sdk.assertions.jwt;


import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.proc.BadJWTException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;

import static org.assertj.core.api.Assertions.assertThat;


public class JWTAssertionDetailsVerifierTest {

    @Test
    public void testRun() {

        Issuer issuer = new Issuer("https://c2id.com");
        URI tokenEndpoint = URI.create("https://c2id.com/token");

        JWTAssertionDetailsVerifier verifier = new JWTAssertionDetailsVerifier(
                new HashSet<>(Arrays.asList(
                        new Audience(issuer),
                        new Audience(tokenEndpoint)
                ))
        );

        assertThat(verifier.getExpectedAudience()).contains(new Audience(issuer));
        assertThat(verifier.getExpectedAudience()).contains(new Audience(tokenEndpoint));
        assertThat(verifier.getExpectedAudience()).hasSize(2);

        // good claims - aud = OP / AS issuer
        verifier.verify(new JWTClaimsSet.Builder()
                .issuer("123")
                .subject("alice")
                .audience(issuer.getValue())
                .expirationTime(new Date(new Date().getTime() + 60 * 1000L))
                .build());

        // good claims - aud = token endpoint
        verifier.verify(new JWTClaimsSet.Builder()
                .issuer("123")
                .subject("alice")
                .audience(tokenEndpoint.toString())
                .expirationTime(new Date(new Date().getTime() + 60 * 1000L))
                .build());

        // empty claims
        BadJWTException exception = Assertions.assertThrows(BadJWTException.class, () -> verifier.verify(new JWTClaimsSet.Builder().build()));
        assertThat(exception.getMessage()).isEqualTo("Missing JWT expiration claim");

        BadJWTException exception1 = Assertions.assertThrows(BadJWTException.class, () ->
                verifier.verify(new JWTClaimsSet.Builder()
                        .expirationTime(new Date(new Date().getTime() + 60 * 1000L))
                        .build()));


        assertThat(exception1.getMessage()).isEqualTo("Missing JWT audience claim");

        BadJWTException exception2 = Assertions.assertThrows(BadJWTException.class, () ->
                verifier.verify(new JWTClaimsSet.Builder()
                        .expirationTime(new Date(new Date().getTime() + 60 * 1000L))
                        .audience(issuer.getValue())
                        .build()));

        assertThat(exception2.getMessage()).isEqualTo("Missing JWT issuer claim");

        BadJWTException exception3 = Assertions.assertThrows(BadJWTException.class, () ->
                verifier.verify(new JWTClaimsSet.Builder()
                        .expirationTime(new Date(new Date().getTime() + 60 * 1000L))
                        .audience(issuer.getValue())
                        .issuer("123")
                        .build()));


        assertThat(exception3.getMessage()).isEqualTo("Missing JWT subject claim");

        BadJWTException exception4 = Assertions.assertThrows(BadJWTException.class, () ->
                verifier.verify(new JWTClaimsSet.Builder()
                        .expirationTime(new Date(new Date().getTime() + 60 * 1000L))
                        .audience(issuer.getValue())
                        .issuer("123")
                        .build()));

        assertThat(exception4.getMessage()).isEqualTo("Missing JWT subject claim");

        BadJWTException exception5 = Assertions.assertThrows(BadJWTException.class, () ->
                verifier.verify(new JWTClaimsSet.Builder()
                        .expirationTime(new Date(new Date().getTime() - 60 * 1000L))
                        .audience(issuer.getValue())
                        .issuer("123")
                        .build()));

        assertThat(exception5.getMessage()).isEqualTo("Expired JWT");

        BadJWTException exception6 = Assertions.assertThrows(BadJWTException.class, () ->
                verifier.verify(new JWTClaimsSet.Builder()
                        .expirationTime(new Date(new Date().getTime() + 60 * 1000L))
                        .audience("bad-audience")
                        .issuer("123")
                        .build()));

        assertThat(exception6.getMessage().startsWith("Invalid JWT audience claim, expected")).isTrue();

    }
}
