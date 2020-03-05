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
package be.atbash.ee.openid.connect.sdk.validators;


import be.atbash.ee.oauth2.sdk.id.State;
import be.atbash.ee.openid.connect.sdk.claims.StateHash;
import be.atbash.ee.security.octopus.nimbus.jwt.jws.JWSAlgorithm;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the state hash validator.
 */
public class StateValidatorTest {

    @Test
    public void testValid()
            throws InvalidHashException {

        State state = new State();
        StateHash sHash = StateHash.compute(state, JWSAlgorithm.HS256);
        StateValidator.validate(state, JWSAlgorithm.HS256, sHash);
    }

    @Test
    public void testUnsupportedAlg() {

        State state = new State();
        StateHash sHash = StateHash.compute(state, JWSAlgorithm.HS256);
        InvalidHashException exception = Assertions.assertThrows(InvalidHashException.class, () ->
                StateValidator.validate(state, new JWSAlgorithm("none"), sHash));

        assertThat(exception.getMessage()).isEqualTo("State hash (s_hash) mismatch");

    }

    @Test
    public void testInvalidHash() {

        State state = new State();
        InvalidHashException exception = Assertions.assertThrows(InvalidHashException.class, () ->
                StateValidator.validate(state, JWSAlgorithm.HS256, new StateHash("xxx")));

        assertThat(exception.getMessage()).isEqualTo("State hash (s_hash) mismatch");

    }
}
