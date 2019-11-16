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
package be.atbash.ee.openid.connect.sdk.validators;


import be.atbash.ee.oauth2.sdk.AuthorizationCode;
import be.atbash.ee.openid.connect.sdk.claims.CodeHash;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;

/**
 * Authorisation code validator, using the {@code c_hash} ID token claim.
 * Required in the hybrid flow where the authorisation code is returned
 * together with an ID token at the authorisation endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.3.2.10.
 * </ul>
 */
// FIXME Will this be used in Octopus?
public class AuthorizationCodeValidator {


    /**
     * Validates the specified authorisation code.
     *
     * @param code         The authorisation code. Must not be
     *                     {@code null}.
     * @param jwsAlgorithm The JWS algorithm of the ID token. Must not
     *                     be {@code null}.=
     * @param codeHash     The authorisation code hash, as set in the
     *                     {@code c_hash} ID token claim. Must not be
     *                     {@code null}.
     * @throws InvalidHashException If the authorisation code doesn't match
     *                              the hash.
     */
    public static void validate(final AuthorizationCode code,
                                final JWSAlgorithm jwsAlgorithm,
                                final CodeHash codeHash)
            throws InvalidHashException {

        CodeHash expectedHash = CodeHash.compute(code, jwsAlgorithm);

        if (expectedHash == null) {
            throw InvalidHashException.INVALID_CODE_HASH_EXCEPTION;
        }

        if (!expectedHash.equals(codeHash)) {
            throw InvalidHashException.INVALID_CODE_HASH_EXCEPTION;
        }
    }
}
