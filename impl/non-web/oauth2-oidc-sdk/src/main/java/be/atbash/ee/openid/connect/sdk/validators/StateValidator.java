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


import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.openid.connect.sdk.claims.StateHash;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;

/**
 * State validator, using the optional {@code s_hash} ID token claim. Required
 * for applications that must comply with Financial Services – Financial API -
 * Part 2: Read and Write API Security Profile.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>Financial Services – Financial API - Part 2: Read and Write API
 *         Security Profile, section 5.1.
 * </ul>
 */
// FIXME Will this be used in Octopus?
public class StateValidator {


    /**
     * Validates the specified state.
     *
     * @param state        The state received at the redirection URI. Must
     *                     not be {@code null}.
     * @param jwsAlgorithm The JWS algorithm of the ID token. Must not be
     *                     be {@code null}.
     * @param stateHash    The state hash, as set in the {@code s_hash} ID
     *                     token claim. Must not be {@code null}.
     * @throws InvalidHashException If the received state doesn't match the
     *                              hash.
     */
    public static void validate(final State state,
                                final JWSAlgorithm jwsAlgorithm,
                                final StateHash stateHash)
            throws InvalidHashException {

        StateHash expectedHash = StateHash.compute(state, jwsAlgorithm);

        if (expectedHash == null) {
            throw InvalidHashException.INVALID_STATE_HASH_EXCEPTION;
        }

        if (!expectedHash.equals(stateHash)) {
            throw InvalidHashException.INVALID_STATE_HASH_EXCEPTION;
        }
    }
}
