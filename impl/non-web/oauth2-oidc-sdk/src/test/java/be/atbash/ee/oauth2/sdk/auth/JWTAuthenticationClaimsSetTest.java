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


import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.JWTID;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.Test;

import javax.json.JsonObject;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the client_secret_jwt and private_key_jwt claims set.
 */
public class JWTAuthenticationClaimsSetTest {

    @Test
    public void testReservedClaimsNames() {

        // http://tools.ietf.org/html/rfc7523#section-3
        assertThat(JWTAuthenticationClaimsSet.getReservedClaimsNames()).contains("iss");
        assertThat(JWTAuthenticationClaimsSet.getReservedClaimsNames()).contains("sub");
        assertThat(JWTAuthenticationClaimsSet.getReservedClaimsNames()).contains("aud");
        assertThat(JWTAuthenticationClaimsSet.getReservedClaimsNames()).contains("exp");
        assertThat(JWTAuthenticationClaimsSet.getReservedClaimsNames()).contains("nbf");
        assertThat(JWTAuthenticationClaimsSet.getReservedClaimsNames()).contains("iat");
        assertThat(JWTAuthenticationClaimsSet.getReservedClaimsNames()).contains("jti");
        assertThat(JWTAuthenticationClaimsSet.getReservedClaimsNames()).hasSize(7);
    }

    @Test
    public void testMinimalConstructor()
            throws Exception {

        ClientID clientID = new ClientID("123");
        Audience aud = new Audience("https://c2id.com/token");

        JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(clientID, aud);

        // Test getters
        assertThat(claimsSet.getClientID()).isEqualTo(clientID);
        assertThat(claimsSet.getIssuer().getValue()).isEqualTo(clientID.getValue());
        assertThat(claimsSet.getSubject().getValue()).isEqualTo(clientID.getValue());
        assertThat(claimsSet.getAudience().get(0)).isEqualTo(aud);

        // 4 min < exp < 6 min
        final long now = new Date().getTime();
        final Date fourMinutesFromNow = new Date(now + 4 * 60 * 1000L);
        final Date sixMinutesFromNow = new Date(now + 6 * 60 * 1000L);
        assertThat(claimsSet.getExpirationTime().after(fourMinutesFromNow)).isTrue();
        assertThat(claimsSet.getExpirationTime().before(sixMinutesFromNow)).isTrue();

        assertThat(claimsSet.getIssueTime()).isNull();
        assertThat(claimsSet.getNotBeforeTime()).isNull();

        assertThat(claimsSet.getJWTID()).isNotNull();
        assertThat(claimsSet.getJWTID().getValue().length()).isEqualTo(new JWTID().getValue().length());

        assertThat(claimsSet.getCustomClaims()).isNull();

        // Test output to JSON object
        JsonObject jsonObject = claimsSet.toJSONObject();
        assertThat(jsonObject.getString("iss")).isEqualTo("123");
        assertThat(jsonObject.getString("sub")).isEqualTo("123");
        List<String> audList = JSONObjectUtils.getStringList(jsonObject, "aud");
        assertThat(audList.get(0)).isEqualTo("https://c2id.com/token");
        assertThat(audList).hasSize(1);
        assertThat(jsonObject.getJsonNumber("exp").longValue()).isEqualTo(claimsSet.getExpirationTime().getTime() / 1000L);
        assertThat(jsonObject.getString("jti")).isEqualTo(claimsSet.getJWTID().getValue());
        assertThat(jsonObject).hasSize(5);

        // Test output to JWT claims set
        JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("123");
        assertThat(jwtClaimsSet.getSubject()).isEqualTo("123");
        assertThat(jwtClaimsSet.getAudience().get(0)).isEqualTo("https://c2id.com/token");
        assertThat(jwtClaimsSet.getAudience()).hasSize(1);
        assertThat(jwtClaimsSet.getExpirationTime().getTime() / 1000).isEqualTo(claimsSet.getExpirationTime().getTime() / 1000L);
        assertThat(jwtClaimsSet.getJWTID()).isEqualTo(claimsSet.getJWTID().getValue());
        assertThat(jwtClaimsSet.toJSONObject()).hasSize(5);

        // Test parse
        JWTAuthenticationClaimsSet parsed = JWTAuthenticationClaimsSet.parse(jwtClaimsSet);
        assertThat(parsed.getClientID()).isEqualTo(clientID);
        assertThat(parsed.getIssuer().getValue()).isEqualTo(clientID.getValue());
        assertThat(parsed.getSubject().getValue()).isEqualTo(clientID.getValue());
        assertThat(parsed.getAudience()).isEqualTo(claimsSet.getAudience());
        assertThat(parsed.getExpirationTime().getTime() / 1000l).isEqualTo(claimsSet.getExpirationTime().getTime() / 1000l);
        assertThat(parsed.getIssueTime()).isNull();
        assertThat(parsed.getNotBeforeTime()).isNull();
        assertThat(parsed.getJWTID()).isEqualTo(claimsSet.getJWTID());
        assertThat(claimsSet.getCustomClaims()).isNull();
    }

    @Test
    public void testMultipleAudiences()
            throws Exception {

        ClientID clientID = new ClientID("123");
        List<Audience> audienceList = Arrays.asList(new Audience("https://c2id.com"), new Audience("https://c2id.com/token"));
        final long now = new Date().getTime() / 1000l * 1000l; // reduce precision
        final Date fiveMinutesFromNow = new Date(now + 4 * 60 * 1000l);

        JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(clientID, audienceList, fiveMinutesFromNow, null, null, null);

        // Test getters
        assertThat(claimsSet.getClientID()).isEqualTo(clientID);
        assertThat(claimsSet.getIssuer().getValue()).isEqualTo(clientID.getValue());
        assertThat(claimsSet.getSubject().getValue()).isEqualTo(clientID.getValue());
        assertThat(claimsSet.getAudience()).isEqualTo(audienceList);
        assertThat(claimsSet.getExpirationTime()).isEqualTo(fiveMinutesFromNow);
        assertThat(claimsSet.getIssueTime()).isNull();
        assertThat(claimsSet.getNotBeforeTime()).isNull();
        assertThat(claimsSet.getJWTID()).isNull();
        assertThat(claimsSet.getCustomClaims()).isNull();

        // Test output to JSON object
        JsonObject jsonObject = claimsSet.toJSONObject();
        assertThat(jsonObject.getString("iss")).isEqualTo("123");
        assertThat(jsonObject.getString("sub")).isEqualTo("123");
        List<String> audList = JSONObjectUtils.getStringList(jsonObject, "aud");
        assertThat(audList.get(0)).isEqualTo("https://c2id.com");
        assertThat(audList.get(1)).isEqualTo("https://c2id.com/token");
        assertThat(audList).hasSize(2);
        assertThat(jsonObject.getJsonNumber("exp").longValue()).isEqualTo(fiveMinutesFromNow.getTime() / 1000L);
        assertThat(jsonObject).hasSize(4);

        // Test output to JWT claims set
        JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo("123");
        assertThat(jwtClaimsSet.getSubject()).isEqualTo("123");
        assertThat(jwtClaimsSet.getAudience().get(0)).isEqualTo("https://c2id.com");
        assertThat(jwtClaimsSet.getAudience().get(1)).isEqualTo("https://c2id.com/token");
        assertThat(jwtClaimsSet.getAudience()).hasSize(2);
        assertThat(jwtClaimsSet.getExpirationTime().getTime() / 1000).isEqualTo(fiveMinutesFromNow.getTime() / 1000l);
        assertThat(jwtClaimsSet.toJSONObject()).hasSize(4);

        // Test parse
        JWTAuthenticationClaimsSet parsed = JWTAuthenticationClaimsSet.parse(jwtClaimsSet);
        assertThat(parsed.getClientID()).isEqualTo(clientID);
        assertThat(parsed.getIssuer().getValue()).isEqualTo(clientID.getValue());
        assertThat(parsed.getSubject().getValue()).isEqualTo(clientID.getValue());
        assertThat(parsed.getAudience()).isEqualTo(audienceList);
        assertThat(parsed.getExpirationTime()).isEqualTo(fiveMinutesFromNow);
        assertThat(parsed.getIssueTime()).isNull();
        assertThat(parsed.getNotBeforeTime()).isNull();
        assertThat(parsed.getJWTID()).isNull();
        assertThat(parsed.getCustomClaims()).isNull();
    }

    @Test
    public void testNullJTI() {

        final long now = new Date().getTime();
        final Date fiveMinutesFromNow = new Date(now + 5 * 60 * 1000l);

        JWTAuthenticationClaimsSet claimsSet = new JWTAuthenticationClaimsSet(
                new ClientID("123"),
                new Audience("https://c2id.com/token").toSingleAudienceList(),
                fiveMinutesFromNow,
                null, // nbf
                null, // iat
                null); // jti

        JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
        assertThat(jwtClaimsSet.getJWTID()).isNull();
    }
}
