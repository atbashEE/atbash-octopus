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
package be.atbash.ee.openid.connect.sdk.claims;


import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;


public class SessionIDTest {

    @Test
    public void testConstructor() {

        UUID uuid = UUID.randomUUID();

        SessionID sid = new SessionID(uuid.toString());

        assertThat(sid.getValue()).isEqualTo(uuid.toString());
    }

    @Test
    public void testEquality() {

        assertThat(new SessionID("abc").equals(new SessionID("abc"))).isTrue();
    }

    @Test
    public void testInequality() {

        assertThat(new SessionID("abc").equals(new SessionID("def"))).isFalse();
    }
}
