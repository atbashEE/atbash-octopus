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
package be.atbash.ee.security.octopus.crypto.hash;

import be.atbash.util.exception.AtbashUnexpectedException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class SecretKeyHashTest {

    @Test
    public void hash() {

        SecretKeyHash hash = new SecretKeyHash("PBKDF2", "password", "salt", 1024);
        assertThat(hash.toHex()).isEqualTo("231AFB7DCD2E860CFD58AB13372BD12C923076C3598A121960320F6FEC8A5698");
        assertThat(hash.toHex().length()).isEqualTo(64);  // Hex is using 2 characters per byte, 32 * 2.

    }

    @Test
    public void hash_unknown() {

        Assertions.assertThrows(AtbashUnexpectedException.class, () -> new SecretKeyHash("SHA-256", "password", "salt", 1024));

    }

    @Test
    public void hash_basics() {
        // See is we vary the input that we have other output (to check if the parameters are actually used.
        SecretKeyHash hash1 = new SecretKeyHash("PBKDF2", "password", "salt", 1024);
        SecretKeyHash hash2 = new SecretKeyHash("PBKDF2", "passwOrd", "salt", 1024);
        SecretKeyHash hash3 = new SecretKeyHash("PBKDF2", "password", "sAlt", 1024);
        SecretKeyHash hash4 = new SecretKeyHash("PBKDF2", "password", "salt", 1023);

        // To verify it is repeateble.
        SecretKeyHash hash5 = new SecretKeyHash("PBKDF2", "password", "salt", 1024);

        assertThat(hash1.toHex()).isNotEqualTo(hash2.toHex());
        assertThat(hash1.toHex()).isNotEqualTo(hash3.toHex());
        assertThat(hash1.toHex()).isNotEqualTo(hash4.toHex());
        assertThat(hash2.toHex()).isNotEqualTo(hash3.toHex());
        assertThat(hash2.toHex()).isNotEqualTo(hash4.toHex());
        assertThat(hash3.toHex()).isNotEqualTo(hash5.toHex());

        assertThat(hash1.toHex()).isEqualTo(hash5.toHex());
    }
}