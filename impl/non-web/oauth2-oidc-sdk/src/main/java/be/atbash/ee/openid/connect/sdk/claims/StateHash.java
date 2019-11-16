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


import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;

/**
 * State hash ({@code s_hash}).
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial Services – Financial API - Part 2: Read and Write API
 *         Security Profile, section 5.1.
 * </ul>
 */
public class StateHash extends HashClaim {


    /**
     * Creates a new state hash with the specified value.
     *
     * @param value The state hash value. Must not be {@code null}.
     */
    public StateHash(final String value) {

        super(value);
    }


    /**
     * Computes the hash for the specified state and reference JSON
     * Web Signature (JWS) algorithm.
     *
     * @param state The state. Must not be {@code null}.
     * @param alg   The reference JWS algorithm. Must not be {@code null}.
     * @return The state hash, or {@code null} if the JWS algorithm is not
     * supported.
     */
    public static StateHash compute(final State state, final JWSAlgorithm alg) {

        String value = computeValue(state, alg);

        if (value == null) {
            return null;
        }

        return new StateHash(value);
    }


    @Override
    public boolean equals(final Object object) {

        return object instanceof StateHash &&
                this.toString().equals(object.toString());
    }
}
