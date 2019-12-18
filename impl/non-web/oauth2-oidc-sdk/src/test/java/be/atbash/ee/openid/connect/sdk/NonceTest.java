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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.id.Identifier;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.Base64Value;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.fail;

/**
 * Tests the Nonce class.
 */
public class NonceTest {

    @Test
    public void testDefaultConstructor() {

        Nonce nonce = new Nonce();

        assertThat(new Base64URLValue(nonce.getValue()).decode().length).isEqualTo(Identifier.DEFAULT_BYTE_LENGTH);
    }

    @Test
    public void testIntConstructor() {

        Nonce nonce = new Nonce(1);

        assertThat(new Base64URLValue(nonce.getValue()).decode().length).isEqualTo(1);

    }

    @Test
    public void testIntConstructorZero() {

        try {
            new Nonce(0);

            fail();

        } catch (IllegalArgumentException e) {

            // ok
        }
    }

    @Test
    public void testIntConstructorNegative() {

        try {
            new Nonce(-1);

            fail();

        } catch (IllegalArgumentException e) {

            // ok
        }
    }

    @Test
    public void testEquality() {

        Nonce n1 = new Nonce("abc");
        Nonce n2 = new Nonce("abc");

        assertThat(n1.equals(n2)).isTrue();
    }

    @Test
    public void testInequality() {

        Nonce n1 = new Nonce("abc");
        Nonce n2 = new Nonce("xyz");

        assertThat(n1.equals(n2)).isFalse();
    }
}