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


import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.oauth2.sdk.id.Audience;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.openid.connect.sdk.Nonce;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import org.junit.Test;

import javax.json.JsonObject;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;


/**
 * Tests the ID token claims set.
 */
public class IDTokenClaimsSetTest {

    @Test
    public void testClaimNameConstants() {

        assertThat(IDTokenClaimsSet.ACR_CLAIM_NAME).isEqualTo("acr");
        assertThat(IDTokenClaimsSet.AMR_CLAIM_NAME).isEqualTo("amr");
        assertThat(IDTokenClaimsSet.AT_HASH_CLAIM_NAME).isEqualTo("at_hash");
        assertThat(IDTokenClaimsSet.AUD_CLAIM_NAME).isEqualTo("aud");
        assertThat(IDTokenClaimsSet.AUTH_TIME_CLAIM_NAME).isEqualTo("auth_time");
        assertThat(IDTokenClaimsSet.AZP_CLAIM_NAME).isEqualTo("azp");
        assertThat(IDTokenClaimsSet.C_HASH_CLAIM_NAME).isEqualTo("c_hash");
        assertThat(IDTokenClaimsSet.S_HASH_CLAIM_NAME).isEqualTo("s_hash");
        assertThat(IDTokenClaimsSet.EXP_CLAIM_NAME).isEqualTo("exp");
        assertThat(IDTokenClaimsSet.IAT_CLAIM_NAME).isEqualTo("iat");
        assertThat(IDTokenClaimsSet.ISS_CLAIM_NAME).isEqualTo("iss");
        assertThat(IDTokenClaimsSet.ISS_CLAIM_NAME).isEqualTo("iss");
        assertThat(IDTokenClaimsSet.NONCE_CLAIM_NAME).isEqualTo("nonce");
        assertThat(IDTokenClaimsSet.SUB_CLAIM_NAME).isEqualTo("sub");
        assertThat(IDTokenClaimsSet.SUB_JWK_CLAIM_NAME).isEqualTo("sub_jwk");
        assertThat(IDTokenClaimsSet.SID_CLAIM_NAME).isEqualTo("sid");
    }

    @Test
    public void testStdClaims() {

        Set<String> stdClaimNames = IDTokenClaimsSet.getStandardClaimNames();

        assertThat(stdClaimNames.contains("iss")).isTrue();
        assertThat(stdClaimNames.contains("sub")).isTrue();
        assertThat(stdClaimNames.contains("aud")).isTrue();
        assertThat(stdClaimNames.contains("exp")).isTrue();
        assertThat(stdClaimNames.contains("iat")).isTrue();
        assertThat(stdClaimNames.contains("auth_time")).isTrue();
        assertThat(stdClaimNames.contains("nonce")).isTrue();
        assertThat(stdClaimNames.contains("at_hash")).isTrue();
        assertThat(stdClaimNames.contains("c_hash")).isTrue();
        assertThat(stdClaimNames.contains("s_hash")).isTrue();
        assertThat(stdClaimNames.contains("acr")).isTrue();
        assertThat(stdClaimNames.contains("amr")).isTrue();
        assertThat(stdClaimNames.contains("azp")).isTrue();
        assertThat(stdClaimNames.contains("sub_jwk")).isTrue();
        assertThat(stdClaimNames.contains("sid")).isTrue();

        assertThat(stdClaimNames).hasSize(15);
    }

    @Test
    public void testReadOnlyJWTClaimsSetConstructor()
            throws Exception {

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("https://c2id.com")
                .subject("alice")
                .audience("client-123")
                .expirationTime(new Date(3_600_000L))
                .issueTime(new Date(1_000L))
                .build();

        IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(claimsSet);
        assertThat(idTokenClaimsSet.getIssuer().getValue()).isEqualTo("https://c2id.com");
        assertThat(idTokenClaimsSet.getSubject().getValue()).isEqualTo("alice");
        assertThat(idTokenClaimsSet.getAudience().get(0).getValue()).isEqualTo("client-123");
        assertThat(idTokenClaimsSet.getExpirationTime().getTime()).isEqualTo(3_600_000L);
        assertThat(idTokenClaimsSet.getIssueTime().getTime()).isEqualTo(1_000L);
    }

    @Test
    public void testParseRoundTrip()
            throws Exception {

        // Example from messages spec

        String json = "{\n" +
                "   \"iss\"       : \"https://server.example.com\",\n" +
                "   \"sub\"       : \"24400320\",\n" +
                "   \"aud\"       : \"s6BhdRkqt3\",\n" +
                "   \"nonce\"     : \"n-0S6_WzA2Mj\",\n" +
                "   \"exp\"       : 1311281970,\n" +
                "   \"iat\"       : 1311280970,\n" +
                "   \"auth_time\" : 1311280969,\n" +
                "   \"acr\"       : \"urn:mace:incommon:iap:silver\",\n" +
                "   \"at_hash\"   : \"MTIzNDU2Nzg5MDEyMzQ1Ng\"\n" +
                " }";

        JWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(json);

        IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(jwtClaimsSet);

        assertThat(idTokenClaimsSet.getIssuer().getValue()).isEqualTo("https://server.example.com");
        assertThat(idTokenClaimsSet.getURLClaim("iss").toString()).isEqualTo("https://server.example.com");
        assertThat(idTokenClaimsSet.getURIClaim("iss").toString()).isEqualTo("https://server.example.com");
        assertThat(idTokenClaimsSet.getSubject().getValue()).isEqualTo("24400320");
        assertThat(idTokenClaimsSet.getAudience().get(0).getValue()).isEqualTo("s6BhdRkqt3");
        assertThat(idTokenClaimsSet.getNonce().getValue()).isEqualTo("n-0S6_WzA2Mj");
        assertThat(DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getExpirationTime())).isEqualTo(1311281970L);
        assertThat(DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getIssueTime())).isEqualTo(1311280970L);
        assertThat(DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getAuthenticationTime())).isEqualTo(1311280969L);
        assertThat(idTokenClaimsSet.getACR().getValue()).isEqualTo("urn:mace:incommon:iap:silver");
        assertThat(idTokenClaimsSet.getAccessTokenHash().getValue()).isEqualTo("MTIzNDU2Nzg5MDEyMzQ1Ng");

        json = idTokenClaimsSet.toJWTClaimsSet().toJSONObject().toString();

        jwtClaimsSet = JWTClaimsSet.parse(json);

        idTokenClaimsSet = new IDTokenClaimsSet(jwtClaimsSet);

        assertThat(idTokenClaimsSet.getIssuer().getValue()).isEqualTo("https://server.example.com");
        assertThat(idTokenClaimsSet.getURLClaim("iss").toString()).isEqualTo("https://server.example.com");
        assertThat(idTokenClaimsSet.getURIClaim("iss").toString()).isEqualTo("https://server.example.com");
        assertThat(idTokenClaimsSet.getSubject().getValue()).isEqualTo("24400320");
        assertThat(idTokenClaimsSet.getAudience().get(0).getValue()).isEqualTo("s6BhdRkqt3");
        assertThat(idTokenClaimsSet.getNonce().getValue()).isEqualTo("n-0S6_WzA2Mj");
        assertThat(DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getExpirationTime())).isEqualTo(1311281970L);
        assertThat(DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getIssueTime())).isEqualTo(1311280970L);
        assertThat(DateUtils.toSecondsSinceEpoch(idTokenClaimsSet.getAuthenticationTime())).isEqualTo(1311280969L);
        assertThat(idTokenClaimsSet.getACR().getValue()).isEqualTo("urn:mace:incommon:iap:silver");
        assertThat(idTokenClaimsSet.getAccessTokenHash().getValue()).isEqualTo("MTIzNDU2Nzg5MDEyMzQ1Ng");
    }

    @Test
    public void testGettersAndSetters()
            throws Exception {

        Issuer issuer = new Issuer("iss");
        Subject subject = new Subject("sub");

        List<Audience> audList = new LinkedList<>();
        audList.add(new Audience("aud"));

        Date expirationTime = DateUtils.fromSecondsSinceEpoch(100000L);
        Date issueTime = DateUtils.fromSecondsSinceEpoch(200000L);

        IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(issuer, subject, audList, expirationTime, issueTime);

        Date authenticationTime = DateUtils.fromSecondsSinceEpoch(300000L);
        idTokenClaimsSet.setAuthenticationTime(authenticationTime);

        Nonce nonce = new Nonce();
        idTokenClaimsSet.setNonce(nonce);

        AccessTokenHash accessTokenHash = new AccessTokenHash("123");
        idTokenClaimsSet.setAccessTokenHash(accessTokenHash);

        CodeHash codeHash = new CodeHash("456");
        idTokenClaimsSet.setCodeHash(codeHash);

        StateHash stateHash = new StateHash("789");
        idTokenClaimsSet.setStateHash(stateHash);

        ACR acr = new ACR("1");
        idTokenClaimsSet.setACR(acr);

        List<AMR> amrList = new LinkedList<>();
        amrList.add(new AMR("A"));
        idTokenClaimsSet.setAMR(amrList);

        AuthorizedParty authorizedParty = new AuthorizedParty("azp");
        idTokenClaimsSet.setAuthorizedParty(authorizedParty);

        // Mandatory claims
        assertThat(idTokenClaimsSet.getIssuer().getValue()).isEqualTo("iss");
        assertThat(idTokenClaimsSet.getSubject().getValue()).isEqualTo("sub");
        assertThat(idTokenClaimsSet.getAudience().get(0).getValue()).isEqualTo("aud");
        assertThat(idTokenClaimsSet.getExpirationTime().getTime() / 1000).isEqualTo(100000L);
        assertThat(idTokenClaimsSet.getIssueTime().getTime() / 1000).isEqualTo(200000L);

        // Optional claims
        assertThat(idTokenClaimsSet.getAuthenticationTime().getTime() / 1000).isEqualTo(300000L);
        assertThat(idTokenClaimsSet.getNonce().getValue()).isEqualTo(nonce.getValue());
        assertThat(idTokenClaimsSet.getAccessTokenHash().getValue()).isEqualTo(accessTokenHash.getValue());
        assertThat(idTokenClaimsSet.getCodeHash().getValue()).isEqualTo(codeHash.getValue());
        assertThat(idTokenClaimsSet.getStateHash().getValue()).isEqualTo(stateHash.getValue());
        assertThat(idTokenClaimsSet.getACR().getValue()).isEqualTo(acr.getValue());
        assertThat(idTokenClaimsSet.getAMR().get(0).getValue()).isEqualTo("A");
        assertThat(idTokenClaimsSet.getAuthorizedParty().getValue()).isEqualTo(authorizedParty.getValue());

        String json = idTokenClaimsSet.toJSONObject().build().toString();

        // Try to JWT claims set too
        idTokenClaimsSet.toJWTClaimsSet();

        idTokenClaimsSet = IDTokenClaimsSet.parse(json);

        // Mandatory claims
        assertThat(idTokenClaimsSet.getIssuer().getValue()).isEqualTo("iss");
        assertThat(idTokenClaimsSet.getSubject().getValue()).isEqualTo("sub");
        assertThat(idTokenClaimsSet.getAudience().get(0).getValue()).isEqualTo("aud");
        assertThat(idTokenClaimsSet.getExpirationTime().getTime() / 1000).isEqualTo(100000L);
        assertThat(idTokenClaimsSet.getIssueTime().getTime() / 1000).isEqualTo(200000L);

        // Optional claims
        assertThat(idTokenClaimsSet.getAuthenticationTime().getTime() / 1000).isEqualTo(300000L);
        assertThat(idTokenClaimsSet.getNonce().getValue()).isEqualTo(nonce.getValue());
        assertThat(idTokenClaimsSet.getAccessTokenHash().getValue()).isEqualTo(accessTokenHash.getValue());
        assertThat(idTokenClaimsSet.getCodeHash().getValue()).isEqualTo(codeHash.getValue());
        assertThat(idTokenClaimsSet.getStateHash().getValue()).isEqualTo(stateHash.getValue());
        assertThat(idTokenClaimsSet.getACR().getValue()).isEqualTo(acr.getValue());
        assertThat(idTokenClaimsSet.getAMR().get(0).getValue()).isEqualTo("A");
        assertThat(idTokenClaimsSet.getAuthorizedParty().getValue()).isEqualTo(authorizedParty.getValue());
    }

    @Test
    public void testStateHash()
            throws Exception {

        IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(
                new Issuer("https://c2id.com"),
                new Subject("alice"),
                new Audience("123").toSingleAudienceList(),
                new Date(60_000L),
                new Date(0L)
        );

        assertThat(idTokenClaimsSet.getStateHash()).isNull();

        // Set / get null
        idTokenClaimsSet.setStateHash(null);
        assertThat(idTokenClaimsSet.getStateHash()).isNull();

        State state = new State();
        StateHash stateHash = StateHash.compute(state, JWSAlgorithm.RS256);

        idTokenClaimsSet.setStateHash(stateHash);

        assertThat(idTokenClaimsSet.getStateHash()).isEqualTo(stateHash);

        JsonObject jsonObject = idTokenClaimsSet.toJSONObject().build();

        assertThat(jsonObject.getString("iss")).isEqualTo("https://c2id.com");
        assertThat(jsonObject.getString("sub")).isEqualTo("alice");
        assertThat(jsonObject.getString("s_hash")).isEqualTo(stateHash.getValue());
        assertThat(jsonObject.getJsonNumber("iat").longValue()).isEqualTo(0L);
        assertThat(jsonObject.getJsonNumber("exp").longValue()).isEqualTo(60L);
        assertThat(JSONObjectUtils.getStringList(jsonObject, "aud").get(0)).isEqualTo("123");
        assertThat(jsonObject).hasSize(6);

        idTokenClaimsSet = IDTokenClaimsSet.parse(jsonObject.toString());

        assertThat(idTokenClaimsSet.getStateHash()).isEqualTo(stateHash);
    }

    @Test
    public void testSingleAudSetAndGetWorkaround()
            throws Exception {

        Issuer issuer = new Issuer("iss");
        Subject subject = new Subject("sub");

        List<Audience> audList = new LinkedList<>();
        audList.add(new Audience("aud"));

        Date expirationTime = DateUtils.fromSecondsSinceEpoch(100000L);
        Date issueTime = DateUtils.fromSecondsSinceEpoch(200000L);

        IDTokenClaimsSet idTokenClaimsSet = new IDTokenClaimsSet(issuer, subject, audList, expirationTime, issueTime);

        idTokenClaimsSet.setClaim("aud", "client-1");

        assertThat(idTokenClaimsSet.getAudience().get(0).getValue()).isEqualTo("client-1");
    }

    @Test
    public void testHasRequiredClaimsCodeFlow()
            throws Exception {

        // See http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken

        ResponseType rt_code = ResponseType.parse("code");
        boolean iatAuthzEndpoint = false;

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
                new Issuer("iss"),
                new Subject("sub"),
                new Audience("aud").toSingleAudienceList(),
                new Date(),
                new Date());

        // c_hash not required, at_hash optional in response_type=code
        assertThat(claimsSet.hasRequiredClaims(rt_code, iatAuthzEndpoint)).isTrue();

        claimsSet.setCodeHash(new CodeHash("c_hash"));
        assertThat(claimsSet.hasRequiredClaims(rt_code, iatAuthzEndpoint)).isTrue();

        claimsSet.setAccessTokenHash(new AccessTokenHash("at_hash"));
        assertThat(claimsSet.hasRequiredClaims(rt_code, iatAuthzEndpoint)).isTrue();
    }

    @Test
    public void testHasRequiredClaimsImplicitFlow()
            throws Exception {

        // See http://openid.net/specs/openid-connect-core-1_0.html#ImplicitIDToken

        ResponseType rt_idToken = ResponseType.parse("id_token");
        ResponseType rt_idToken_token = ResponseType.parse("id_token token");
        boolean iatAuthzEndpoint = true;

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
                new Issuer("iss"),
                new Subject("sub"),
                new Audience("aud").toSingleAudienceList(),
                new Date(),
                new Date());

        // nonce always required
        assertThat(claimsSet.hasRequiredClaims(rt_idToken, iatAuthzEndpoint)).isFalse();
        assertThat(claimsSet.hasRequiredClaims(rt_idToken_token, iatAuthzEndpoint)).isFalse();

        claimsSet.setNonce(new Nonce());

        // at_hash required in id_token token, not in id_token
        assertThat(claimsSet.hasRequiredClaims(rt_idToken, iatAuthzEndpoint)).isTrue();
        assertThat(claimsSet.hasRequiredClaims(rt_idToken_token, iatAuthzEndpoint)).isFalse();

        claimsSet.setAccessTokenHash(new AccessTokenHash("at_hash"));

        assertThat(claimsSet.hasRequiredClaims(rt_idToken, iatAuthzEndpoint)).isTrue();
        assertThat(claimsSet.hasRequiredClaims(rt_idToken_token, iatAuthzEndpoint)).isTrue();
    }

    @Test
    public void testHasRequiredClaimsHybridFlow()
            throws Exception {

        // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
        // See http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken2

        ResponseType rt_code_idToken = ResponseType.parse("code id_token");
        ResponseType rt_code_token = ResponseType.parse("code token");
        ResponseType rt_code_idToken_token = ResponseType.parse("code id_token token");

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
                new Issuer("iss"),
                new Subject("sub"),
                new Audience("aud").toSingleAudienceList(),
                new Date(),
                new Date());

        // Nonce always required in hybrid flow, regardless of issue endpoint
        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken, true)).isFalse();
        assertThat(claimsSet.hasRequiredClaims(rt_code_token, true)).isFalse();
        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken_token, true)).isFalse();
        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken, false)).isFalse();
        assertThat(claimsSet.hasRequiredClaims(rt_code_token, false)).isFalse();
        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken_token, false)).isFalse();

        claimsSet.setNonce(new Nonce());

        // at_hash and c_hash not required when id_token issued at token endpoint
        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken, false)).isTrue();
        assertThat(claimsSet.hasRequiredClaims(rt_code_token, false)).isTrue();
        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken_token, false)).isTrue();

        // c_hash required with 'code id_token' and 'code id_token token' issued at authz endpoint
        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken, true)).isFalse();
        assertThat(claimsSet.hasRequiredClaims(rt_code_token, true)).isTrue();
        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken_token, true)).isFalse();

        claimsSet.setCodeHash(new CodeHash("c_hash"));

        // at_hash required with 'code id_token token' issued at authz endpoint
        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken, true)).isTrue();
        assertThat(claimsSet.hasRequiredClaims(rt_code_token, true)).isTrue();
        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken_token, true)).isFalse();

        claimsSet.setAccessTokenHash(new AccessTokenHash("at_hash"));

        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken, true)).isTrue();
        assertThat(claimsSet.hasRequiredClaims(rt_code_token, true)).isTrue();
        assertThat(claimsSet.hasRequiredClaims(rt_code_idToken_token, true)).isTrue();
    }

    @Test
    public void testRequiredClaims_unsupportedResponseType() {

        ResponseType responseType = new ResponseType("token");

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
                new Issuer("iss"),
                new Subject("sub"),
                new Audience("aud").toSingleAudienceList(),
                new Date(),
                new Date());

        try {
            claimsSet.hasRequiredClaims(responseType, true);
            fail();
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("Unsupported response_type: token");
        }
    }

    @Test
    public void testSubjectJWK()
            throws Exception {

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
                new Issuer("iss"),
                new Subject("sub"),
                new Audience("aud").toSingleAudienceList(),
                new Date(),
                new Date());

        assertThat(claimsSet.getSubjectJWK()).isNull();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512);

        KeyPair keyPair = keyGen.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

        RSAKey rsaJWK = new RSAKey.Builder(publicKey).keyID("1").build();

        claimsSet.setSubjectJWK(rsaJWK);

        RSAKey rsaJWKOut = (RSAKey) claimsSet.getSubjectJWK();

        assertThat(rsaJWKOut.getModulus()).isEqualTo(rsaJWK.getModulus());
        assertThat(rsaJWKOut.getPublicExponent()).isEqualTo(rsaJWK.getPublicExponent());
        assertThat(rsaJWKOut.getKeyID()).isEqualTo(rsaJWK.getKeyID());


        String json = claimsSet.toJSONObject().build().toString();

//		System.out.println("ID token with subject JWK: " + json);

        claimsSet = IDTokenClaimsSet.parse(json);

        rsaJWKOut = (RSAKey) claimsSet.getSubjectJWK();

        assertThat(rsaJWKOut.getModulus()).isEqualTo(rsaJWK.getModulus());
        assertThat(rsaJWKOut.getPublicExponent()).isEqualTo(rsaJWK.getPublicExponent());
        assertThat(rsaJWKOut.getKeyID()).isEqualTo(rsaJWK.getKeyID());
    }

    @Test
    public void testRejectPrivateSubjectJWK()
            throws Exception {

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
                new Issuer("iss"),
                new Subject("sub"),
                new Audience("aud").toSingleAudienceList(),
                new Date(),
                new Date());

        assertThat(claimsSet.getSubjectJWK()).isNull();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(512);

        KeyPair keyPair = keyGen.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaJWK = new RSAKey.Builder(publicKey).privateKey(privateKey).build();

        try {
            claimsSet.setSubjectJWK(rsaJWK);

            fail();

        } catch (IllegalArgumentException e) {
            // ok
        }
    }

    @Test
    public void testStringClaim() {

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
                new Issuer("iss"),
                new Subject("sub"),
                new Audience("aud").toSingleAudienceList(),
                new Date(),
                new Date());

        claimsSet.setClaim("xString", "apples");

        assertThat(claimsSet.getStringClaim("xString")).isEqualTo("apples");

        assertThat(claimsSet.getStringClaim("exp")).isNull();
    }

    @Test
    public void testNumberClaim() {

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
                new Issuer("iss"),
                new Subject("sub"),
                new Audience("aud").toSingleAudienceList(),
                new Date(),
                new Date());

        claimsSet.setClaim("xInteger", 10);

        assertThat(claimsSet.getNumberClaim("xInteger").intValue()).isEqualTo(10);

        assertThat(claimsSet.getNumberClaim("iss")).isNull();
    }

    @Test
    public void testURLClaim()
            throws Exception {

        IDTokenClaimsSet claimsSet = new IDTokenClaimsSet(
                new Issuer("iss"),
                new Subject("sub"),
                new Audience("aud").toSingleAudienceList(),
                new Date(),
                new Date());

        claimsSet.setURLClaim("xURL", new URL("http://example.com"));

        assertThat(claimsSet.getURLClaim("xURL").toString()).isEqualTo("http://example.com");

        assertThat(claimsSet.getURLClaim("sub")).isNull();
    }
}
