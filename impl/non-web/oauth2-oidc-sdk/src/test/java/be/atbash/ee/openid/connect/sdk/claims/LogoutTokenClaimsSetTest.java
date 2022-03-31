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
package be.atbash.ee.openid.connect.sdk.claims;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.id.*;
import be.atbash.ee.openid.connect.sdk.Nonce;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import java.net.URI;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


public class LogoutTokenClaimsSetTest {

    @Test
    public void testEventTypeConstant() {

        assertThat(LogoutTokenClaimsSet.EVENT_TYPE).isEqualTo("http://schemas.openid.net/event/backchannel-logout");
    }

    @Test
    public void testStandardClaimNames() {

        Set<String> claimNames = LogoutTokenClaimsSet.getStandardClaimNames();
        assertThat(claimNames.contains("iss")).isTrue();
        assertThat(claimNames.contains("sub")).isTrue();
        assertThat(claimNames.contains("aud")).isTrue();
        assertThat(claimNames.contains("iat")).isTrue();
        assertThat(claimNames.contains("jti")).isTrue();
        assertThat(claimNames.contains("events")).isTrue();
        assertThat(claimNames.contains("sid")).isTrue();
        assertThat(claimNames).hasSize(7);
    }

    @Test
    public void testWithSubject()
            throws Exception {

        Issuer iss = new Issuer(URI.create("https://c2id.com"));
        Subject sub = new Subject("alice");
        List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
        Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
        JWTID jti = new JWTID();

        LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, sub, audList, iat, jti, null);

        assertThat(claimsSet.getIssuer()).isEqualTo(iss);
        assertThat(claimsSet.getSubject()).isEqualTo(sub);
        assertThat(claimsSet.getAudience()).isEqualTo(audList);
        assertThat(claimsSet.getIssueTime()).isEqualTo(iat);
        assertThat(claimsSet.getJWTID()).isEqualTo(jti);
        assertThat(claimsSet.getSessionID()).isNull();

        JsonObject jsonObject = claimsSet.toJSONObject().build();

        assertThat(jsonObject.getString("iss")).isEqualTo(iss.getValue());
        assertThat(jsonObject.getString("sub")).isEqualTo(sub.getValue());
        assertThat(JSONObjectUtils.getStringList(jsonObject, "aud")).isEqualTo(Collections.singletonList("123"));
        assertThat(jsonObject.getJsonNumber("iat").longValue()).isEqualTo(DateUtils.toSecondsSinceEpoch(iat));
        assertThat(jsonObject.getString("jti")).isEqualTo(jti.getValue());
        JsonObject events = jsonObject.getJsonObject("events");
        JsonObject eventType = events.getJsonObject(LogoutTokenClaimsSet.EVENT_TYPE);
        assertThat(eventType.isEmpty()).isTrue();

        claimsSet = LogoutTokenClaimsSet.parse(jsonObject.toString());

        assertThat(claimsSet.getIssuer()).isEqualTo(iss);
        assertThat(claimsSet.getSubject()).isEqualTo(sub);
        assertThat(claimsSet.getAudience()).isEqualTo(audList);
        assertThat(claimsSet.getIssueTime()).isEqualTo(iat);
        assertThat(claimsSet.getJWTID()).isEqualTo(jti);
        assertThat(claimsSet.getSessionID()).isNull();

        JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo(iss.getValue());
        assertThat(jwtClaimsSet.getSubject()).isEqualTo(sub.getValue());
        assertThat(jwtClaimsSet.getAudience()).isEqualTo(Collections.singletonList("123"));
        assertThat(jwtClaimsSet.getIssueTime()).isEqualTo(iat);
        assertThat(jwtClaimsSet.getJWTID()).isEqualTo(jti.getValue());
        assertThat(jwtClaimsSet.getClaim("sid")).isNull();
    }

    @Test
    public void testWithSessionID()
            throws Exception {

        Issuer iss = new Issuer(URI.create("https://c2id.com"));
        List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
        Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
        JWTID jti = new JWTID();
        SessionID sid = new SessionID(UUID.randomUUID().toString());

        LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, null, audList, iat, jti, sid);

        assertThat(claimsSet.getIssuer()).isEqualTo(iss);
        assertThat(claimsSet.getSubject()).isNull();
        assertThat(claimsSet.getAudience()).isEqualTo(audList);
        assertThat(claimsSet.getIssueTime()).isEqualTo(iat);
        assertThat(claimsSet.getJWTID()).isEqualTo(jti);
        assertThat(claimsSet.getSessionID()).isEqualTo(sid);

        JsonObject jsonObject = claimsSet.toJSONObject().build();

        assertThat(jsonObject.getString("iss")).isEqualTo(iss.getValue());
        assertThat(JSONObjectUtils.getStringList(jsonObject, "aud")).isEqualTo(Collections.singletonList("123"));
        assertThat(jsonObject.getJsonNumber("iat").longValue()).isEqualTo(DateUtils.toSecondsSinceEpoch(iat));
        assertThat(jsonObject.getString("jti")).isEqualTo(jti.getValue());
        assertThat(jsonObject.getString("sid")).isEqualTo(sid.getValue());
        JsonObject events = jsonObject.getJsonObject("events");
        JsonObject eventType = events.getJsonObject(LogoutTokenClaimsSet.EVENT_TYPE);
        assertThat(eventType.isEmpty()).isTrue();

        claimsSet = LogoutTokenClaimsSet.parse(jsonObject.toString());

        assertThat(claimsSet.getIssuer()).isEqualTo(iss);
        assertThat(claimsSet.getSubject()).isNull();
        assertThat(claimsSet.getAudience()).isEqualTo(audList);
        assertThat(claimsSet.getIssueTime()).isEqualTo(iat);
        assertThat(claimsSet.getJWTID()).isEqualTo(jti);
        assertThat(claimsSet.getSessionID()).isEqualTo(sid);

        JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo(iss.getValue());
        assertThat(jwtClaimsSet.getAudience()).isEqualTo(Collections.singletonList("123"));
        assertThat(jwtClaimsSet.getIssueTime()).isEqualTo(iat);
        assertThat(jwtClaimsSet.getJWTID()).isEqualTo(jti.getValue());
        assertThat(jwtClaimsSet.getClaim("sid")).isEqualTo(sid.getValue());
    }

    @Test
    public void testWithSubjectAndSessionID()
            throws Exception {

        Issuer iss = new Issuer(URI.create("https://c2id.com"));
        Subject sub = new Subject("alice");
        List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
        Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
        JWTID jti = new JWTID();
        SessionID sid = new SessionID(UUID.randomUUID().toString());

        LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, sub, audList, iat, jti, sid);

        assertThat(claimsSet.getIssuer()).isEqualTo(iss);
        assertThat(claimsSet.getSubject()).isEqualTo(sub);
        assertThat(claimsSet.getAudience()).isEqualTo(audList);
        assertThat(claimsSet.getIssueTime()).isEqualTo(iat);
        assertThat(claimsSet.getJWTID()).isEqualTo(jti);
        assertThat(claimsSet.getSessionID()).isEqualTo(sid);

        JsonObject jsonObject = claimsSet.toJSONObject().build();

        assertThat(jsonObject.getString("iss")).isEqualTo(iss.getValue());
        assertThat(jsonObject.getString("sub")).isEqualTo(sub.getValue());
        assertThat(JSONObjectUtils.getStringList(jsonObject, "aud")).isEqualTo(Collections.singletonList("123"));
        assertThat(jsonObject.getJsonNumber("iat").longValue()).isEqualTo(DateUtils.toSecondsSinceEpoch(iat));
        assertThat(jsonObject.getString("jti")).isEqualTo(jti.getValue());
        assertThat(jsonObject.getString("sid")).isEqualTo(sid.getValue());
        JsonObject events = jsonObject.getJsonObject("events");
        JsonObject eventType = events.getJsonObject(LogoutTokenClaimsSet.EVENT_TYPE);
        assertThat(eventType.isEmpty()).isTrue();

        claimsSet = LogoutTokenClaimsSet.parse(jsonObject.toString());

        assertThat(claimsSet.getIssuer()).isEqualTo(iss);
        assertThat(claimsSet.getSubject()).isEqualTo(sub);
        assertThat(claimsSet.getAudience()).isEqualTo(audList);
        assertThat(claimsSet.getIssueTime()).isEqualTo(iat);
        assertThat(claimsSet.getJWTID()).isEqualTo(jti);
        assertThat(claimsSet.getSessionID()).isEqualTo(sid);

        JWTClaimsSet jwtClaimsSet = claimsSet.toJWTClaimsSet();
        assertThat(jwtClaimsSet.getIssuer()).isEqualTo(iss.getValue());
        assertThat(jwtClaimsSet.getSubject()).isEqualTo(sub.getValue());
        assertThat(jwtClaimsSet.getAudience()).isEqualTo(Collections.singletonList("123"));
        assertThat(jwtClaimsSet.getIssueTime()).isEqualTo(iat);
        assertThat(jwtClaimsSet.getJWTID()).isEqualTo(jti.getValue());
        assertThat(jwtClaimsSet.getClaim("sid")).isEqualTo(sid.getValue());
    }

    @Test
    public void testNonceProhibited_output() {

        Issuer iss = new Issuer(URI.create("https://c2id.com"));
        Subject sub = new Subject("alice");
        List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
        Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
        JWTID jti = new JWTID();
        SessionID sid = new SessionID(UUID.randomUUID().toString());

        LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, sub, audList, iat, jti, sid);
        claimsSet.setClaim("nonce", new Nonce().getValue());

        IllegalStateException exception = Assertions.assertThrows(IllegalStateException.class, () ->
                claimsSet.toJSONObject());

        assertThat(exception.getMessage()).isEqualTo("Nonce is prohibited");

        OAuth2JSONParseException exception1 = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                claimsSet.toJWTClaimsSet());

        assertThat(exception1.getMessage()).isEqualTo("Nonce is prohibited");

    }

    @Test
    public void testNonceProhibited_parse()
            throws OAuth2JSONParseException {

        Issuer iss = new Issuer(URI.create("https://c2id.com"));
        Subject sub = new Subject("alice");
        List<Audience> audList = new Audience(new ClientID("123")).toSingleAudienceList();
        Date iat = DateUtils.fromSecondsSinceEpoch(10203040L);
        JWTID jti = new JWTID();
        SessionID sid = new SessionID(UUID.randomUUID().toString());

        LogoutTokenClaimsSet claimsSet = new LogoutTokenClaimsSet(iss, sub, audList, iat, jti, sid);

        JsonObjectBuilder jsonObject = claimsSet.toJSONObject();
        jsonObject.add("nonce", new Nonce().getValue());

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                LogoutTokenClaimsSet.parse(jsonObject.build().toString()));

        assertThat(exception.getMessage()).isEqualTo("Nonce is prohibited");


        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder(claimsSet.toJWTClaimsSet())
                .claim("nonce", new Nonce().getValue())
                .build();

        exception = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                new LogoutTokenClaimsSet(jwtClaimsSet));

        assertThat(exception.getMessage()).isEqualTo("Nonce is prohibited");

    }

    @Test
    public void testConstructorSubAndSIDMissing() {

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () ->
                new LogoutTokenClaimsSet(
                        new Issuer("https://c2id.com"),
                        null,
                        new Audience("123").toSingleAudienceList(),
                        new Date(),
                        new JWTID(),
                        null));


        assertThat(exception.getMessage()).isEqualTo("Either the subject or the session ID must be set, or both");

    }

    @Test
    public void testParseEventTypeMissing() {

        String json = "{\n" +
                "   \"iss\": \"https://server.example.com\",\n" +
                "   \"sub\": \"248289761001\",\n" +
                "   \"aud\": \"s6BhdRkqt3\",\n" +
                "   \"iat\": 1471566154,\n" +
                "   \"jti\": \"bWJq\",\n" +
                "   \"sid\": \"08a5019c-17e1-4977-8f42-65a12843ea02\"\n" +
                "  }";

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                LogoutTokenClaimsSet.parse(json));

        assertThat(exception.getMessage()).isEqualTo("Missing or invalid \"events\" claim");

    }
}
