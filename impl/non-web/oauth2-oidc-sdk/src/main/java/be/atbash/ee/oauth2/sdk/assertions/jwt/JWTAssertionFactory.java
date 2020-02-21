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


import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.ECDSASigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.MACSigner;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.RSASSASigner;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSHeader;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;


/**
 * Static JWT bearer assertion factory.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Assertion Framework for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7521).
 *     <li>JSON Web Token (JWT) Profile for OAuth 2.0 Client Authentication and
 *         Authorization Grants (RFC 7523).
 * </ul>
 */
public class JWTAssertionFactory {


    /**
     * Returns the supported signature JSON Web Algorithms (JWAs).
     *
     * @return The supported JSON Web Algorithms (JWAs).
     */
    public static Set<JWSAlgorithm> supportedJWAs() {

        Set<JWSAlgorithm> supported = new HashSet<>();
        supported.addAll(JWSAlgorithm.Family.HMAC_SHA);
        supported.addAll(JWSAlgorithm.Family.RSA);
        supported.addAll(JWSAlgorithm.Family.EC);
        return Collections.unmodifiableSet(supported);
    }


    /**
     * Creates a new HMAC-protected JWT bearer assertion.
     *
     * @param details      The JWT bearer assertion details. Must not be
     *                     {@code null}.
     * @param jwsAlgorithm The expected HMAC algorithm (HS256, HS384 or
     *                     HS512) for the JWT assertion. Must be supported
     *                     and not {@code null}.
     * @param secret       The secret. Must be at least 256-bits long.
     * @return The JWT bearer assertion.
     */
    public static SignedJWT create(JWTAssertionDetails details,
                                   JWSAlgorithm jwsAlgorithm,
                                   Secret secret) {

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(jwsAlgorithm), details.toJWTClaimsSet());
        signedJWT.sign(new MACSigner(secret.getValueBytes()));
        return signedJWT;
    }


    /**
     * Creates a new RSA-signed JWT bearer assertion.
     *
     * @param details       The JWT bearer assertion details. Must not be
     *                      be {@code null}.
     * @param jwsAlgorithm  The expected RSA signature algorithm (RS256,
     *                      RS384, RS512, PS256, PS384 or PS512) for the
     *                      JWT assertion. Must be supported and not
     *                      {@code null}.
     * @param rsaPrivateKey The RSA private key. Must not be {@code null}.
     * @param keyID         Optional identifier for the RSA key, to aid key
     *                      selection on the recipient side. Recommended.
     *                      {@code null} if not specified.
     * @return The JWT bearer assertion.
     */
    public static SignedJWT create(JWTAssertionDetails details,
                                   JWSAlgorithm jwsAlgorithm,
                                   RSAPrivateKey rsaPrivateKey,
                                   String keyID) {

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(jwsAlgorithm).keyID(keyID).build(),
                details.toJWTClaimsSet());
        RSASSASigner signer = new RSASSASigner(rsaPrivateKey);
        signedJWT.sign(signer);
        return signedJWT;
    }


    /**
     * Creates a new EC-signed JWT bearer assertion.
     *
     * @param details      The JWT bearer assertion details. Must not be
     *                     {@code null}.
     * @param jwsAlgorithm The expected EC signature algorithm (ES256,
     *                     ES384 or ES512) for the JWT assertion. Must be
     *                     supported and not {@code null}.
     * @param ecPrivateKey The EC private key. Must not be {@code null}.
     * @param keyID        Optional identifier for the EC key, to aid key
     *                     selection on the recipient side. Recommended.
     *                     {@code null} if not specified.
     * @return The JWT bearer assertion.
     */
    public static SignedJWT create(JWTAssertionDetails details,
                                   JWSAlgorithm jwsAlgorithm,
                                   ECPrivateKey ecPrivateKey,
                                   String keyID) {

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(jwsAlgorithm).keyID(keyID).build(),
                details.toJWTClaimsSet());
        ECDSASigner signer = new ECDSASigner(ecPrivateKey);
        signedJWT.sign(signer);
        return signedJWT;
    }


    /**
     * Prevents public instantiation.
     */
    private JWTAssertionFactory() {
    }
}
