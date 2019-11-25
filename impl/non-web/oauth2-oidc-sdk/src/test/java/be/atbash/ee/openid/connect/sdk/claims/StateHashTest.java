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
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.assertj.core.api.Assertions.assertThat;


public class StateHashTest {

    @Test
    public void testCompute()
            throws Exception {

        State state = new State("abc");

        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] hash = sha512.digest(state.getValue().getBytes(StandardCharsets.US_ASCII));

        assertThat(ByteUtils.bitLength(hash)).isEqualTo(512);

        byte[] truncatedHash = ByteUtils.subArray(hash, 0, hash.length / 2);

        assertThat(ByteUtils.bitLength(truncatedHash)).isEqualTo(256);

        assertThat(StateHash.compute(state, JWSAlgorithm.HS512).getValue()).isEqualTo(Base64URLValue.encode(truncatedHash).toString());
    }

    @Test
    public void testEquality() {

        assertThat(new StateHash("abc").equals(new StateHash("abc"))).isTrue();
    }

    @Test
    public void testInequality() {

        assertThat(new StateHash("abc").equals(new StateHash("ABC"))).isFalse();
        assertThat(new StateHash("abc").equals(null)).isFalse();
    }

    @Test
    public void testUnsupportedJWSAlg() {

        assertThat(StateHash.compute(new State(), new JWSAlgorithm("no-such-alg"))).isNull();
    }
}
