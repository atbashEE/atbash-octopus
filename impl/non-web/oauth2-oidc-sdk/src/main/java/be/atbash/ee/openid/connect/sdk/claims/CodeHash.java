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


import be.atbash.ee.oauth2.sdk.AuthorizationCode;
import be.atbash.ee.oauth2.sdk.ResponseType;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;


/**
 * Authorisation code hash ({@code c_hash}).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 3.3.2.11.
 * </ul>
 */
public final class CodeHash extends HashClaim {


    /**
     * Checks if an authorisation code hash claim must be included in ID
     * tokens for the specified response type.
     *
     * @param responseType The he OpenID Connect response type. Must not be
     *                     {@code null}.
     * @return {@code true} if the code hash is required, else
     * {@code false}.
     */
    public static boolean isRequiredInIDTokenClaims(ResponseType responseType) {

        // Only required in hybrid flow for 'code id_token' and 'code id_token token'
        // Disregard authz / token endpoint!
        return new ResponseType("code", "id_token").equals(responseType) ||
                new ResponseType("code", "id_token", "token").equals(responseType);

    }


    /**
     * Creates a new authorisation code hash with the specified value.
     *
     * @param value The authorisation code hash value. Must not be
     *              {@code null}.
     */
    public CodeHash(String value) {

        super(value);
    }


    /**
     * Computes the hash for the specified authorisation code and reference
     * JSON Web Signature (JWS) algorithm.
     *
     * @param code The authorisation code. Must not be {@code null}.
     * @param alg  The reference JWS algorithm. Must not be {@code null}.
     * @return The authorisation code hash, or {@code null} if the JWS
     * algorithm is not supported.
     */
    public static CodeHash compute(AuthorizationCode code, JWSAlgorithm alg) {

        String value = computeValue(code, alg);

        if (value == null) {
            return null;
        }

        return new CodeHash(value);
    }


    @Override
    public boolean equals(Object object) {

        return object instanceof CodeHash &&
                this.toString().equals(object.toString());
    }
}
