/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package be.atbash.ee.oauth2.sdk.id;


import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

/**
 * Tests random state value generation.
 */
public class StateTest {

    @Test
    public void testValueConstructor() {

        String value = "abc";

        State state = new State(value);

        assertThat(state.getValue()).isEqualTo(value);
        assertThat(state.toString()).isEqualTo(value);
    }


    @Test
    public void testEmptyValue() {

        try {
            new State("");

            fail("Failed to raise exception");

        } catch (IllegalArgumentException e) {

            // ok
        }
    }

    @Test
    public void testEquality() {

        State s1 = new State("abc");

        State s2 = new State("abc");

        assertThat(s1.equals(s2)).isTrue();
    }

    @Test
    public void testInequality() {

        State s1 = new State("abc");

        State s2 = new State("def");

        assertThat(s1.equals(s2)).isFalse();
    }

    @Test
    public void testInequalityNull() {

        State s1 = new State("abc");

        assertThat(s1.equals(null)).isFalse();
    }

    @Test
    public void testHashCode() {

        State s1 = new State("abc");

        State s2 = new State("abc");

        assertThat(s2.hashCode()).isEqualTo(s1.hashCode());
    }

    @Test
    public void testGeneration() {

        State state = new State();


        assertThat(new Base64URLValue(state.toString()).decode().length).isEqualTo(Identifier.DEFAULT_BYTE_LENGTH);
    }

    @Test
    public void testGenerationVarLength() {

        State state = new State(16);


        assertThat(new Base64Value(state.toString()).decode().length).isEqualTo(16);
    }

    @Test
    public void testJSONValue() {

        State state = new State("abc");

        String json = state.toJSONString();

        assertThat(json).isEqualTo("\"abc\"");
    }
}
