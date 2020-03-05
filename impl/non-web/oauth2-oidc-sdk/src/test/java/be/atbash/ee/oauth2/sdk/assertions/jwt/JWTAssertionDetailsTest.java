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
import be.atbash.ee.oauth2.sdk.id.JWTID;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.jupiter.api.Test;

import javax.json.JsonObject;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the JWT bearer assertion details (claims set).
 */
public class JWTAssertionDetailsTest {

    @Test
    public void testReservedClaimsNames() {

        // http://tools.ietf.org/html/rfc7523#section-3
        assertThat(JWTAssertionDetails.getReservedClaimsNames()).contains("iss");
        assertThat(JWTAssertionDetails.getReservedClaimsNames()).contains("sub");
        assertThat(JWTAssertionDetails.getReservedClaimsNames()).contains("aud");
        assertThat(JWTAssertionDetails.getReservedClaimsNames()).contains("exp");
        assertThat(JWTAssertionDetails.getReservedClaimsNames()).contains("nbf");
        assertThat(JWTAssertionDetails.getReservedClaimsNames()).contains("iat");
        assertThat(JWTAssertionDetails.getReservedClaimsNames()).contains("jti");
        assertThat(JWTAssertionDetails.getReservedClaimsNames()).hasSize(7);
    }


    @Test
    public void testMinimalConstructor()
            throws Exception {

        Issuer iss = new Issuer("http://example.com");
        Subject sub = new Subject("alice");
        Audience aud = new Audience("https://c2id.com/token");

        JWTAssertionDetails claimsSet = new JWTAssertionDetails(iss, sub, aud);

        // Test getters
        assertThat(claimsSet.getIssuer()).isEqualTo(iss);
        assertThat(claimsSet.getSubject()).isEqualTo(sub);
        assertThat(claimsSet.getAudience().get(0)).isEqualTo(aud);

        // 4 min < exp < 6 min
        long now = new Date().getTime();
        Date fourMinutesFromNow = new Date(now + 4 * 60 * 1000L);
        Date sixMinutesFromNow = new Date(now + 6 * 60 * 1000L);
        assertThat(claimsSet.getExpirationTime().after(fourMinutesFromNow)).isTrue();
        assertThat(claimsSet.getExpirationTime().before(sixMinutesFromNow)).isTrue();

        assertThat(claimsSet.getIssueTime()).isNull();
        assertThat(claimsSet.getNotBeforeTime()).isNull();

        assertThat(claimsSet.getJWTID()).isNotNull();
        assertThat(claimsSet.getJWTID().getValue().length()).isEqualTo(new JWTID().getValue().length());

        assertThat(claimsSet.getCustomClaims()).isNull();

        // Test output to JSON object
        JsonObject jsonObject = claimsSet.toJSONObject();
        assertThat(jsonObject.getString("iss")).isEqualTo("http://example.com");
        assertThat(jsonObject.getString("sub")).isEqualTo("alice");
        List<String> audList = JSONObjectUtils.getStringList(jsonObject, "aud");
        assertThat(audList.get(0)).isEqualTo("https://c2id.com/token");
        assertThat(audList).hasSize(1);
        assertThat(jsonObject.getJsonNumber("exp").longValue()).isEqualTo(claimsSet.getExpirationTime().getTime() / 1000l);
        assertThat(jsonObject.getString("jti")).isEqualTo(claimsSet.getJWTID().getValue());
        assertThat(jsonObject).hasSize(5);

        // Test output to JWT claims set
        JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("http://example.com");
        assertThat(jwtClaimsSet.getSubject()).isEqualTo("alice");
        assertThat(jwtClaimsSet.getAudience().get(0)).isEqualTo("https://c2id.com/token");
        assertThat(jwtClaimsSet.getAudience()).hasSize(1);
        assertThat(jwtClaimsSet.getExpirationTime().getTime() / 1000).isEqualTo(claimsSet.getExpirationTime().getTime() / 1000l);
        assertThat(jwtClaimsSet.getJWTID()).isEqualTo(claimsSet.getJWTID().getValue());
        assertThat(jwtClaimsSet.toJSONObject()).hasSize(5);

        // Test parse
        JWTAssertionDetails parsed = JWTAssertionDetails.parse(jwtClaimsSet);
        assertThat(parsed.getIssuer()).isEqualTo(iss);
        assertThat(parsed.getSubject()).isEqualTo(sub);
        assertThat(parsed.getAudience().get(0)).isEqualTo(aud);
        assertThat(parsed.getExpirationTime().getTime() / 1000l).isEqualTo(claimsSet.getExpirationTime().getTime() / 1000l);
        assertThat(parsed.getIssueTime()).isNull();
        assertThat(parsed.getNotBeforeTime()).isNull();
        assertThat(parsed.getJWTID()).isEqualTo(claimsSet.getJWTID());
        assertThat(claimsSet.getCustomClaims()).isNull();
    }

    @Test
    public void testWithOtherClaims()
            throws Exception {

        Map<String, Object> other = new LinkedHashMap<>();
        other.put("A", "B");
        other.put("ten", 10L);

        JWTAssertionDetails claimsSet = new JWTAssertionDetails(
                new Issuer("123"),
                new Subject("alice"),
                new Audience("https://c2id.com/token").toSingleAudienceList(),
                new Date(),
                null,
                null,
                null,
                other);

        assertThat(claimsSet.getCustomClaims()).isEqualTo(other);

        // Test output to JSON object
        JsonObject jsonObject = claimsSet.toJSONObject();

        assertThat(jsonObject.getString("iss")).isEqualTo("123");
        assertThat(jsonObject.getString("sub")).isEqualTo("alice");
        assertThat(JSONObjectUtils.getStringList(jsonObject, "aud").get(0)).isEqualTo("https://c2id.com/token");
        assertThat(JSONObjectUtils.getStringList(jsonObject, "aud")).hasSize(1);
        assertThat(jsonObject.get("exp")).isNotNull();
        assertThat(jsonObject.getString("A")).isEqualTo("B");
        assertThat(jsonObject.getJsonNumber("ten").longValue()).isEqualTo(10L);
        assertThat(jsonObject).hasSize(6);

        // Test output to JWT claims set
        JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("123");
        assertThat(jwtClaimsSet.getSubject()).isEqualTo("alice");
        assertThat(jwtClaimsSet.getAudience().get(0)).isEqualTo("https://c2id.com/token");
        assertThat(jwtClaimsSet.getAudience()).hasSize(1);
        assertThat(jwtClaimsSet.getExpirationTime()).isNotNull();
        assertThat(jwtClaimsSet.getStringClaim("A")).isEqualTo("B");
        assertThat(jwtClaimsSet.getLongClaim("ten").longValue()).isEqualTo(10L);

        // Test parse
        JWTAssertionDetails parsed = JWTAssertionDetails.parse(jwtClaimsSet);
        assertThat(parsed.getIssuer().getValue()).isEqualTo("123");
        assertThat(parsed.getSubject().getValue()).isEqualTo("alice");
        assertThat(parsed.getAudience().get(0).getValue()).isEqualTo("https://c2id.com/token");
        assertThat(parsed.getExpirationTime().getTime() / 1000l).isEqualTo(claimsSet.getExpirationTime().getTime() / 1000l);
        assertThat(parsed.getIssueTime()).isNull();
        assertThat(parsed.getNotBeforeTime()).isNull();
        assertThat(parsed.getJWTID()).isEqualTo(claimsSet.getJWTID());
        assertThat(claimsSet.getCustomClaims()).isNotNull();
        other = claimsSet.getCustomClaims();
        assertThat(other.get("A")).isEqualTo("B");
        assertThat(other.get("ten")).isEqualTo(10l);
        assertThat(other).hasSize(2);
    }
}
