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


import be.atbash.ee.oauth2.sdk.token.AccessToken;
import be.atbash.ee.openid.connect.sdk.claims.AccessTokenHash;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;

/**
 * Access token validator, using the {@code at_hash} ID token claim. Required
 * in the implicit flow and the hybrid flow where the access token is returned
 * at the authorisation endpoint.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 3.1.3.8, 3.2.2.9 and 3.3.2.9.
 * </ul>
 */
// FIXME Will this be used in Octopus?
public class AccessTokenValidator {


    /**
     * Validates the specified access token.
     *
     * @param accessToken     The access token. Must not be {@code null}.
     * @param jwsAlgorithm    The JWS algorithm of the ID token. Must not
     *                        be {@code null}.
     * @param accessTokenHash The access token hash, as set in the
     *                        {@code at_hash} ID token claim. Must not be
     *                        {@code null},
     * @throws InvalidHashException If the access token doesn't match the
     *                              hash.
     */
    public static void validate(final AccessToken accessToken,
                                final JWSAlgorithm jwsAlgorithm,
                                final AccessTokenHash accessTokenHash)
            throws InvalidHashException {

        AccessTokenHash expectedHash = AccessTokenHash.compute(accessToken, jwsAlgorithm);

        if (expectedHash == null) {
            throw InvalidHashException.INVALID_ACCESS_T0KEN_HASH_EXCEPTION;
        }

        if (!expectedHash.equals(accessTokenHash)) {
            throw InvalidHashException.INVALID_ACCESS_T0KEN_HASH_EXCEPTION;
        }
    }
}
