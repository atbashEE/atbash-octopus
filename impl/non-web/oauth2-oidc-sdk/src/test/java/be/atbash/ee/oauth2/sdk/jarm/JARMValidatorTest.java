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

import be.atbash.ee.oauth2.sdk.AuthorizationCode;
import be.atbash.ee.oauth2.sdk.AuthorizationSuccessResponse;
import be.atbash.ee.oauth2.sdk.ResponseMode;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.openid.connect.sdk.TestKeySelector;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSAEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jwk.KeyUse;
import be.atbash.ee.security.octopus.nimbus.jwk.RSAKey;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTClaimsSet;
import be.atbash.ee.security.octopus.nimbus.jwt.JWTParser;
import be.atbash.ee.security.octopus.nimbus.jwt.PlainJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.proc.BadJWTException;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import be.atbash.ee.security.octopus.util.HmacSecretUtil;
import org.junit.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

public class JARMValidatorTest {
    private static final RSAKey SERVER_RSA_JWK;

    private static final AuthorizationSuccessResponse SAMPLE_AUTHZ_RESPONSE =
            new AuthorizationSuccessResponse(
                    URI.create("https://client.example.com/cb"),
                    new AuthorizationCode(),
                    null,
                    new State(),
                    ResponseMode.QUERY_JWT
            );


    static {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair keyPair = gen.generateKeyPair();
            SERVER_RSA_JWK = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID("1")
                    .keyUse(KeyUse.SIGNATURE)
                    .build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    @Test
    public void testRejectPlain()
            throws Exception {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");

        JARMValidator jarmValidator = new JARMValidator(iss, clientID, new TestKeySelector(null));

        JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
                iss,
                clientID,
                new Date(), //Instant.now().plus(1000L).toDate(),
                SAMPLE_AUTHZ_RESPONSE);

        PlainJWT jarm = new PlainJWT(claimsSet);

        try {
            jarmValidator.validate(jarm);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("The JWT must not be plain (unsecured)");
        }
    }

    @Test
    public void testVerifySigned()
            throws Exception {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Date exp = new Date((new Date().getTime() / 1000 * 1000) + 1000);

        JARMValidator jarmValidator = new JARMValidator(iss, clientID, new TestKeySelector(SERVER_RSA_JWK.toRSAPublicKey()));

        JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
                iss,
                clientID,
                exp,
                SAMPLE_AUTHZ_RESPONSE);

        SignedJWT jarm = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        jarm.sign(new RSASSASigner(SERVER_RSA_JWK));

        claimsSet = jarmValidator.validate(jarm);
        assertThat(claimsSet.getIssuer()).isEqualTo(iss.getValue());
        assertThat(claimsSet.getAudience().get(0)).isEqualTo(clientID.getValue());
        assertThat(claimsSet.getExpirationTime()).isEqualTo(exp);
        assertThat(claimsSet.getStringClaim("state")).isEqualTo(SAMPLE_AUTHZ_RESPONSE.getState().getValue());
        assertThat(claimsSet.getStringClaim("code")).isEqualTo(SAMPLE_AUTHZ_RESPONSE.getAuthorizationCode().getValue());
    }

    @Test
    public void testRejectBadSignature()
            throws Exception {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Date exp = new Date((new Date().getTime() / 1000 * 1000) + 1000);

        JARMValidator jarmValidator = new JARMValidator(iss, clientID, new TestKeySelector(SERVER_RSA_JWK.toRSAPublicKey()));

        JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
                iss,
                clientID,
                exp,
                SAMPLE_AUTHZ_RESPONSE);

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();
        RSAKey invalidRSAJWK = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID("1")
                .keyUse(KeyUse.SIGNATURE)
                .build();

        SignedJWT jarm = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claimsSet);
        jarm.sign(new RSASSASigner(invalidRSAJWK));

        try {
            jarmValidator.validate(jarm);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Signed JWT rejected: Invalid signature");
        }
    }

    @Test
    public void testVerifyHMAC()
            throws Exception {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Date exp = new Date((new Date().getTime() / 1000 * 1000) + 1000);

        Secret clientSecret = new Secret(ByteUtils.byteLength(256));

        AtbashKey atbashKey = HmacSecretUtil.generateSecretKey("someId", clientSecret.getValueBytes());

        JARMValidator jarmValidator = new JARMValidator(iss, clientID, new TestKeySelector(atbashKey.getKey()));

        JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
                iss,
                clientID,
                exp,
                SAMPLE_AUTHZ_RESPONSE);

        SignedJWT jarm = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        jarm.sign(new MACSigner(clientSecret.getValueBytes()));

        claimsSet = jarmValidator.validate(jarm);
        assertThat(claimsSet.getIssuer()).isEqualTo(iss.getValue());
        assertThat(claimsSet.getAudience().get(0)).isEqualTo(clientID.getValue());
        assertThat(claimsSet.getExpirationTime()).isEqualTo(exp);
        assertThat(claimsSet.getStringClaim("state")).isEqualTo(SAMPLE_AUTHZ_RESPONSE.getState().getValue());
        assertThat(claimsSet.getStringClaim("code")).isEqualTo(SAMPLE_AUTHZ_RESPONSE.getAuthorizationCode().getValue());
    }

    @Test
    public void testRejectBadHMAC()
            throws Exception {

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Date exp = new Date((new Date().getTime() / 1000 * 1000) + 1000);

        Secret clientSecret = new Secret(ByteUtils.byteLength(256));
        AtbashKey atbashKey = HmacSecretUtil.generateSecretKey("someId", clientSecret.getValueBytes());

        JARMValidator jarmValidator = new JARMValidator(iss, clientID, new TestKeySelector(atbashKey.getKey()));

        JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
                iss,
                clientID,
                exp,
                SAMPLE_AUTHZ_RESPONSE);

        SignedJWT jarm = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        jarm.sign(new MACSigner(new Secret(ByteUtils.byteLength(256)).getValueBytes()));

        try {
            jarmValidator.validate(jarm);
            fail();
        } catch (BadJWTException e) {
            assertThat(e.getMessage()).isEqualTo("Signed JWT rejected: Invalid signature");
        }
    }

    @Test
    public void testVerifyNested()
            throws Exception {


        // Generate RP key
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();
        RSAKey rpJWK = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID("e1")
                .keyUse(KeyUse.ENCRYPTION)
                .build();

        Issuer iss = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Date exp = new Date((new Date().getTime() / 1000 * 1000) + 1000);

        JWTClaimsSet claimsSet = JARMUtils.toJWTClaimsSet(
                iss,
                clientID,
                exp,
                SAMPLE_AUTHZ_RESPONSE);

        SignedJWT jarm = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(SERVER_RSA_JWK.getKeyID()).build(), claimsSet);
        jarm.sign(new RSASSASigner(SERVER_RSA_JWK));

        JWEObject jweObject = new JWEObject(new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256).keyID("e1").contentType("JWT").build(), new Payload(jarm));
        jweObject.encrypt(new RSAEncrypter(rpJWK));

        String jarmJWTString = jweObject.serialize();

        JARMValidator jarmValidator = new JARMValidator(
                iss,
                clientID,
                new TestKeySelector(SERVER_RSA_JWK.toRSAPublicKey()),
                new TestKeySelector(rpJWK.toRSAPrivateKey())
        );

        assertThat(jarmValidator.getExpectedIssuer()).isEqualTo(iss);
        assertThat(jarmValidator.getClientID()).isEqualTo(clientID);

        claimsSet = jarmValidator.validate(JWTParser.parse(jarmJWTString));
        assertThat(claimsSet.getIssuer()).isEqualTo(iss.getValue());
        assertThat(claimsSet.getAudience().get(0)).isEqualTo(clientID.getValue());
        assertThat(claimsSet.getExpirationTime()).isEqualTo(exp);
        assertThat(claimsSet.getStringClaim("state")).isEqualTo(SAMPLE_AUTHZ_RESPONSE.getState().getValue());
        assertThat(claimsSet.getStringClaim("code")).isEqualTo(SAMPLE_AUTHZ_RESPONSE.getAuthorizationCode().getValue());
    }

}