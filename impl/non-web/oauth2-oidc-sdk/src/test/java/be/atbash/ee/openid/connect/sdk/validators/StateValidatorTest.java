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
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

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
        try {
            StateValidator.validate(state, new JWSAlgorithm("none"), sHash);
            fail();
        } catch (InvalidHashException e) {
            assertThat(e.getMessage()).isEqualTo("State hash (s_hash) mismatch");
        }
    }

    @Test
    public void testInvalidHash() {

        State state = new State();
        try {
            StateValidator.validate(state, JWSAlgorithm.HS256, new StateHash("xxx"));
            fail();
        } catch (InvalidHashException e) {
            assertThat(e.getMessage()).isEqualTo("State hash (s_hash) mismatch");
        }
    }
}
