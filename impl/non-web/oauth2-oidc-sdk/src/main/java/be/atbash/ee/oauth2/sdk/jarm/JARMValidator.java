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


import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.Issuer;
import be.atbash.ee.openid.connect.sdk.validators.AbstractJWTValidator;
import be.atbash.ee.security.octopus.keys.selector.KeySelector;
import be.atbash.ee.security.octopus.nimbus.jwt.*;
import be.atbash.ee.security.octopus.nimbus.jwt.proc.BadJWTException;
import be.atbash.ee.security.octopus.nimbus.jwt.proc.DefaultJWTProcessor;

import java.text.ParseException;


/**
 * Validator of JSON Web Token (JWT) secured authorisation responses (JARM).
 *
 * <p>Supports processing of JWT responses with the following protection:
 *
 * <ul>
 *     <li>JWTs signed (JWS) with the Authorisation Server's RSA or EC key,
 *         require the Authorisation Server's public JWK set (provided by value
 *         or URL) to verify them.
 *     <li>JWTs authenticated with a JWS HMAC, require the client's secret
 *         to verify them.
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial-grade API: JWT Secured Authorization Response Mode for
 *         OAuth 2.0 (JARM).
 * </ul>
 */
public class JARMValidator extends AbstractJWTValidator {


    /**
     * Creates a new JARM validator for RSA or EC signed authorisation
     * responses where the Authorisation Server's JWK set is specified by
     * value.
     *
     * @param expectedIssuer The expected issuer (Authorisation Server).
     *                       Must not be {@code null}.
     * @param clientID       The client ID. Must not be {@code null}.
     */
    public JARMValidator(Issuer expectedIssuer,
                         ClientID clientID,
                         KeySelector keySelector) {

        this(expectedIssuer, clientID, keySelector, null);
    }

    /**
     * Creates a new JARM validator.
     *
     * @param expectedIssuer The expected issuer (Authorisation Server).
     *                       Must not be {@code null}.
     * @param clientID       The client ID. Must not be {@code null}.
     * @param jwsKeySelector The key selector for JWS verification, must
     *                       not be {@code null}.
     * @param jweKeySelector The key selector for JWE decryption,
     *                       {@code null} if encrypted authorisation
     *                       responses are not expected.
     */
    public JARMValidator(Issuer expectedIssuer,
                         ClientID clientID,
                         KeySelector jwsKeySelector,
                         KeySelector jweKeySelector) {

        super(expectedIssuer, clientID, jwsKeySelector, jweKeySelector);
    }


    /**
     * Validates the specified JWT-secured authorisation response.
     *
     * @param jwtResponseString The JWT-secured authorisation response
     *                          string. Must not be {@code null}.
     * @return The claims set of the verified JWT.
     */
    public JWTClaimsSet validate(String jwtResponseString) {

        try {
            return validate(JWTParser.parse(jwtResponseString));
        } catch (ParseException e) {
            throw new BadJWTException("Invalid JWT: " + e.getMessage(), e);
        }
    }


    /**
     * Validates the specified JWT-secured authorisation response.
     *
     * @param jwtResponse The JWT-secured authorisation response. Must not
     *                    be {@code null}.
     * @return The claims set of the verified JWT.
     */
    public JWTClaimsSet validate(JWT jwtResponse) {

        if (jwtResponse instanceof SignedJWT) {
            return validate((SignedJWT) jwtResponse);
        } else if (jwtResponse instanceof EncryptedJWT) {
            return validate((EncryptedJWT) jwtResponse);
        } else if (jwtResponse instanceof PlainJWT) {
            throw new BadJWTException("The JWT must not be plain (unsecured)");
        } else {
            throw new BadJWTException("Unexpected JWT type: " + jwtResponse.getClass());
        }
    }


    /**
     * Verifies the specified signed authorisation response.
     *
     * @param jwtResponse The JWT-secured authorisation response. Must not
     *                    be {@code null}.
     * @return The claims set of the verified JWT.
     */
    private JWTClaimsSet validate(SignedJWT jwtResponse) {

        if (getJWSKeySelector() == null) {
            throw new BadJWTException("Verification of signed JWTs not configured");
        }

        DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        jwtProcessor.setJWSKeySelector(getJWSKeySelector());
        jwtProcessor.setJWTClaimsSetVerifier(new JARMClaimsVerifier(getExpectedIssuer(), getClientID(), getMaxClockSkew()));
        return jwtProcessor.process(jwtResponse);
    }


    /**
     * Verifies the specified signed and encrypted authorisation response.
     *
     * @param jwtResponse The JWT-secured authorisation response. Must not
     *                    be {@code null}.
     * @return The claims set of the verified JWT.
     */
    private JWTClaimsSet validate(EncryptedJWT jwtResponse) {

        if (getJWEKeySelector() == null) {
            throw new BadJWTException("Decryption of JWTs not configured");
        }
        if (getJWSKeySelector() == null) {
            throw new BadJWTException("Verification of signed JWTs not configured");
        }

        DefaultJWTProcessor jwtProcessor = new DefaultJWTProcessor();
        jwtProcessor.setJWSKeySelector(getJWSKeySelector());
        jwtProcessor.setJWEKeySelector(getJWEKeySelector());
        jwtProcessor.setJWTClaimsSetVerifier(new JARMClaimsVerifier(getExpectedIssuer(), getClientID(), getMaxClockSkew()));

        return jwtProcessor.process(jwtResponse);
    }

}
