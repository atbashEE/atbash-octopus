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
package be.atbash.ee.oauth2.sdk.jarm;

import be.atbash.ee.oauth2.sdk.*;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.openid.connect.sdk.AuthenticationSuccessResponse;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSAEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jwt.*;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

public class JARMUtilsTest {
    private static final RSAPrivateKey RSA_PRIVATE_KEY;

    private static final RSAPublicKey RSA_PUBLIC_KEY;

    static {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair keyPair = gen.generateKeyPair();
            RSA_PRIVATE_KEY = (RSAPrivateKey) keyPair.getPrivate();
            RSA_PUBLIC_KEY = (RSAPublicKey) keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void testToJWTClaimsSet_successResponse() throws ParseException {

        Issuer issuer = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Date exp = new Date(); // now
        AuthorizationSuccessResponse response = new AuthorizationSuccessResponse(
                URI.create("https://exmaple.com?cb"),
                new AuthorizationCode(),
                null,
                new State(),
                null
        );

        JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
                issuer,
                clientID,
                exp,
                response
        );

        assertThat(jwtClaimsSet.getIssuer()).isEqualTo(issuer.getValue());
        assertThat(jwtClaimsSet.getAudience().get(0)).isEqualTo(clientID.getValue());
        assertThat(DateUtils.toSecondsSinceEpoch(jwtClaimsSet.getExpirationTime())).isEqualTo(DateUtils.toSecondsSinceEpoch(exp));

        assertThat(jwtClaimsSet.getStringClaim("code")).isEqualTo(response.getAuthorizationCode().getValue());
        assertThat(jwtClaimsSet.getStringClaim("state")).isEqualTo(response.getState().getValue());

        assertThat(jwtClaimsSet.getClaims().size()).isEqualTo(5);
    }

    @Test
    public void testToJWTClaimsSet_oidcAuthSuccessResponse() throws ParseException {

        Issuer issuer = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Date exp = new Date(); // now
        AuthenticationSuccessResponse response = new AuthenticationSuccessResponse(
                URI.create("https://exmaple.com?cb"),
                new AuthorizationCode(),
                null,
                null,
                new State(),
                new State(), // session_state
                null
        );

        JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
                issuer,
                clientID,
                exp,
                response
        );

        assertThat(jwtClaimsSet.getIssuer()).isEqualTo(issuer.getValue());
        assertThat(jwtClaimsSet.getAudience().get(0)).isEqualTo(clientID.getValue());
        assertThat(DateUtils.toSecondsSinceEpoch(jwtClaimsSet.getExpirationTime())).isEqualTo(DateUtils.toSecondsSinceEpoch(exp));

        assertThat(jwtClaimsSet.getStringClaim("code")).isEqualTo(response.getAuthorizationCode().getValue());
        assertThat(jwtClaimsSet.getStringClaim("state")).isEqualTo(response.getState().getValue());
        assertThat(jwtClaimsSet.getStringClaim("session_state")).isEqualTo(response.getSessionState().getValue());

        assertThat(jwtClaimsSet.getClaims().size()).isEqualTo(6);
    }

    @Test
    public void testToJWTClaimsSet_errorResponse() throws ParseException {

        Issuer issuer = new Issuer("https://c2id.com");
        ClientID clientID = new ClientID("123");
        Date exp = new Date(); // now
        AuthorizationErrorResponse response = new AuthorizationErrorResponse(
                URI.create("https://exmaple.com?cb"),
                OAuth2Error.ACCESS_DENIED,
                new State(),
                null
        );

        JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(
                issuer,
                clientID,
                exp,
                response
        );

        assertThat(jwtClaimsSet.getIssuer()).isEqualTo(issuer.getValue());
        assertThat(jwtClaimsSet.getAudience().get(0)).isEqualTo(clientID.getValue());
        assertThat(DateUtils.toSecondsSinceEpoch(jwtClaimsSet.getExpirationTime())).isEqualTo(DateUtils.toSecondsSinceEpoch(exp));


        assertThat(jwtClaimsSet.getStringClaim("state")).isEqualTo(response.getState().getValue());
        assertThat(jwtClaimsSet.getStringClaim("error")).isEqualTo(OAuth2Error.ACCESS_DENIED.getCode());
        assertThat(jwtClaimsSet.getStringClaim("error_description")).isEqualTo(OAuth2Error.ACCESS_DENIED.getDescription());
        assertThat(jwtClaimsSet.getClaims().size()).isEqualTo(6);
    }

    @Test
    public void testToJWTClaimsSet_issNotNull() {

        try {
            JARMUtils.toJWTClaimsSet(
                    null,
                    new ClientID("123"),
                    new Date(),
                    new AuthorizationSuccessResponse(
                            URI.create("https://exmaple.com?cb"),
                            new AuthorizationCode(),
                            null,
                            new State(),
                            null
                    )
            );
        } catch (NullPointerException e) {
            // ok
        }
    }

    @Test
    public void testToJWTClaimsSet_audNotNull() {

        try {
            JARMUtils.toJWTClaimsSet(
                    new Issuer("https://c2id.com"),
                    null,
                    new Date(),
                    new AuthorizationSuccessResponse(
                            URI.create("https://exmaple.com?cb"),
                            new AuthorizationCode(),
                            null,
                            new State(),
                            null
                    )
            );
        } catch (NullPointerException e) {
            // ok
        }
    }

    @Test
    public void testToJWTClaimsSet_expNotNull() {

        try {
            JARMUtils.toJWTClaimsSet(
                    new Issuer("https://c2id.com"),
                    new ClientID("123"),
                    null,
                    new AuthorizationSuccessResponse(
                            URI.create("https://exmaple.com?cb"),
                            new AuthorizationCode(),
                            null,
                            new State(),
                            null
                    )
            );
        } catch (IllegalArgumentException e) {
            assertThat(e.getMessage()).isEqualTo("The expiration time must not be null");
        }
    }

    @Test
    public void testImpliesAuthorizationErrorResponse_positive()
            throws Exception {

        AuthorizationErrorResponse response = new AuthorizationErrorResponse(
                URI.create("https://exmaple.com?cb"),
                OAuth2Error.ACCESS_DENIED,
                new State(),
                null
        );

        JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(new Issuer("https://c2id.com"), new ClientID("123"), new Date(), response);
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
        jwt.sign(new RSASSASigner(RSA_PRIVATE_KEY));

        assertThat(JARMUtils.impliesAuthorizationErrorResponse(jwt)).isTrue();
    }

    @Test
    public void testImpliesAuthorizationErrorResponse_negative()
            throws Exception {

        JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder().build(); // simply no "error" claim
        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
        jwt.sign(new RSASSASigner(RSA_PRIVATE_KEY));

        assertThat(JARMUtils.impliesAuthorizationErrorResponse(jwt)).isFalse();
    }

    @Test
    public void testImpliesAuthorizationErrorResponse_rejectPlain() {

        AuthorizationErrorResponse response = new AuthorizationErrorResponse(
                URI.create("https://exmaple.com?cb"),
                OAuth2Error.ACCESS_DENIED,
                new State(),
                null
        );

        JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(new Issuer("https://c2id.com"), new ClientID("123"), new Date(), response);
        JWT jwt = new PlainJWT(jwtClaimsSet);

        OAuth2JSONParseException exception = Assertions.assertThrows(OAuth2JSONParseException.class, () ->
                JARMUtils.impliesAuthorizationErrorResponse(jwt));
        assertThat(exception.getMessage()).isEqualTo("Invalid JWT-secured authorization response: The JWT must not be plain (unsecured)");
    }

    @Test
    public void testImpliesAuthorizationErrorResponse_encryptedJWTAlwaysAssumesSuccessfulResponse()
            throws Exception {

        AuthorizationErrorResponse response = new AuthorizationErrorResponse(
                URI.create("https://exmaple.com?cb"),
                OAuth2Error.ACCESS_DENIED,
                new State(),
                null
        );

        JWTClaimsSet jwtClaimsSet = JARMUtils.toJWTClaimsSet(new Issuer("https://c2id.com"), new ClientID("123"), new Date(), response);
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtClaimsSet);
        signedJWT.sign(new RSASSASigner(RSA_PRIVATE_KEY));

        JWEObject jweObject = new JWEObject(new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128GCM), new Payload(signedJWT));
        jweObject.encrypt(new RSAEncrypter(RSA_PUBLIC_KEY));

        JWT jwt = JWTParser.parse(jweObject.serialize());

        assertThat(JARMUtils.impliesAuthorizationErrorResponse(jwt)).isFalse();
    }
}