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
package be.atbash.ee.openid.connect.sdk.claims;


import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import org.junit.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


public class AggregatedClaimsTest {


    static final KeyPair RSA_KEY_PAIR;


    static {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            RSA_KEY_PAIR = gen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }


    static JWT createClaimsJWT() {
        JsonObjectBuilder claims = Json.createObjectBuilder();

        claims.add("email", "alice@wonderland.net");
        claims.add("email_verified", true);
        return createClaimsJWT(claims.build());
    }


    static JWT createClaimsJWT(final JsonObject claims) {

        try {
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.RS256),
                    JWTClaimsSet.parse(claims)
            );

            jwt.sign(new RSASSASigner(RSA_KEY_PAIR.getPrivate()));

            return jwt;

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testMinConstructor() {

        Set<String> claimNames = new HashSet<>(Arrays.asList("email", "email_verified"));
        JWT claimsJWT = createClaimsJWT();

        AggregatedClaims aggregatedClaims = new AggregatedClaims(claimNames, claimsJWT);

        UUID sourceUUID = UUID.fromString(aggregatedClaims.getSourceID());
        assertThat(sourceUUID).isNotNull();

        assertThat(aggregatedClaims.getNames()).isEqualTo(claimNames);
        assertThat(aggregatedClaims.getClaimsJWT()).isEqualTo(claimsJWT);


        JsonObject claimsJSONObject = aggregatedClaims.mergeInto(Json.createObjectBuilder().build());

        JsonObject claimNamesJSONObject = (JsonObject) claimsJSONObject.get("_claim_names");
        assertThat(claimNamesJSONObject.getString("email")).isEqualTo(sourceUUID.toString());
        assertThat(claimNamesJSONObject.getString("email_verified")).isEqualTo(sourceUUID.toString());
        assertThat(claimNamesJSONObject).hasSize(2);

        JsonObject claimSourcesJSONObject = claimsJSONObject.getJsonObject("_claim_sources");
        JsonObject claimsSourceSpec = (JsonObject) claimSourcesJSONObject.get(sourceUUID.toString());
        assertThat(claimsSourceSpec.getString("JWT")).isEqualTo(claimsJWT.serialize());
        assertThat(claimsSourceSpec).hasSize(1);

        assertThat(claimSourcesJSONObject).hasSize(1);

        assertThat(claimsJSONObject).hasSize(2);
    }

    @Test
    public void testMainConstructor() {

        String sourceID = "src1";
        Set<String> claimNames = new HashSet<>(Arrays.asList("email", "email_verified"));
        JWT claimsJWT = createClaimsJWT();

        AggregatedClaims aggregatedClaims = new AggregatedClaims(sourceID, claimNames, claimsJWT);

        assertThat(aggregatedClaims.getSourceID()).isEqualTo(sourceID);
        assertThat(aggregatedClaims.getNames()).isEqualTo(claimNames);
        assertThat(aggregatedClaims.getClaimsJWT()).isEqualTo(claimsJWT);


        JsonObject claimsJSONObject = aggregatedClaims.mergeInto(Json.createObjectBuilder().build());

        JsonObject claimNamesJSONObject = claimsJSONObject.getJsonObject("_claim_names");
        assertThat(claimNamesJSONObject.getString("email")).isEqualTo(sourceID);
        assertThat(claimNamesJSONObject.getString("email_verified")).isEqualTo(sourceID);
        assertThat(claimNamesJSONObject).hasSize(2);

        JsonObject claimSourcesJSONObject = claimsJSONObject.getJsonObject("_claim_sources");
        JsonObject claimsSourceSpec = claimSourcesJSONObject.getJsonObject(sourceID);
        assertThat(claimsSourceSpec.getString("JWT")).isEqualTo(claimsJWT.serialize());
        assertThat(claimsSourceSpec).hasSize(1);

        assertThat(claimSourcesJSONObject).hasSize(1);

        assertThat(claimsJSONObject).hasSize(2);
    }

    @Test
    public void testMergeTwoSources() {

        String src1 = "src1";

        JsonObjectBuilder claims1builder = Json.createObjectBuilder();
        claims1builder.add("email", "alice@wonderland.net");
        claims1builder.add("email_verified", true);

        JsonObject claims1 = claims1builder.build();
        JWT jwt1 = createClaimsJWT(claims1);

        AggregatedClaims aggregatedClaims1 = new AggregatedClaims(
                src1,
                claims1.keySet(),
                jwt1);

        assertThat(aggregatedClaims1.getSourceID()).isEqualTo(src1);
        assertThat(aggregatedClaims1.getNames()).isEqualTo(claims1.keySet());
        assertThat(aggregatedClaims1.getClaimsJWT().serialize()).isEqualTo(jwt1.serialize());

        JsonObject jsonObject = aggregatedClaims1.mergeInto(Json.createObjectBuilder().build());

        String src2 = "src2";

        JsonObjectBuilder claims2builder = Json.createObjectBuilder();
        claims2builder.add("score", "100");

        JsonObject claims2 = claims2builder.build();
        JWT jwt2 = createClaimsJWT(claims2);

        AggregatedClaims aggregatedClaims2 = new AggregatedClaims(
                src2,
                claims2.keySet(),
                jwt2);

        assertThat(aggregatedClaims2.getSourceID()).isEqualTo(src2);
        assertThat(aggregatedClaims2.getNames()).isEqualTo(claims2.keySet());
        assertThat(aggregatedClaims2.getClaimsJWT().serialize()).isEqualTo(jwt2.serialize());

        jsonObject = aggregatedClaims2.mergeInto(jsonObject);

        JsonObject claimNamesJSONObject = jsonObject.getJsonObject("_claim_names");
        assertThat(claimNamesJSONObject.getString("email")).isEqualTo(src1);
        assertThat(claimNamesJSONObject.getString("email_verified")).isEqualTo(src1);
        assertThat(claimNamesJSONObject.getString("score")).isEqualTo(src2);
        assertThat(claimNamesJSONObject).hasSize(3);

        JsonObject claimSourcesJSONObject = jsonObject.getJsonObject("_claim_sources");
        JsonObject claimsSource1Spec = claimSourcesJSONObject.getJsonObject(src1);
        assertThat(claimsSource1Spec.getString("JWT")).isEqualTo(jwt1.serialize());
        assertThat(claimsSource1Spec).hasSize(1);
        JsonObject claimsSource2Spec = claimSourcesJSONObject.getJsonObject(src2);
        assertThat(claimsSource2Spec.getString("JWT")).isEqualTo(jwt2.serialize());
        assertThat(claimsSource2Spec).hasSize(1);

        assertThat(claimSourcesJSONObject).hasSize(2);

        assertThat(jsonObject).hasSize(2);
    }

    @Test
    public void testRejectNullSourceID() {

        try {
            new AggregatedClaims(null, Collections.singleton("score"), createClaimsJWT());
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The claims source identifier must not be null or empty");
        }
    }

    @Test
    public void testRejectEmptySourceID() {

        try {
            new AggregatedClaims("", Collections.singleton("score"), createClaimsJWT());
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The claims source identifier must not be null or empty");
        }
    }

    @Test
    public void testRejectNullClaimNames() {

        try {
            new AggregatedClaims("src1", null, createClaimsJWT());
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The claim names must not be null or empty");
        }
    }

    @Test
    public void testRejectEmptyClaimNames() {

        try {
            new AggregatedClaims("src1", Collections.<String>emptySet(), createClaimsJWT());
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The claim names must not be null or empty");
        }
    }

    @Test
    public void testRejectNullJWT() {

        try {
            new AggregatedClaims("src1", Collections.singleton("score"), null);
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The claims JWT must not be null");
        }
    }
}
