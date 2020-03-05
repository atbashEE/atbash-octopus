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

import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.crypto.MissingSaltException;
import be.atbash.util.codec.ByteSource;
import be.atbash.util.codec.CodecException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
public class HashFactoryTest extends AbstractKeyNameTest {

    private HashFactory factory;

    @BeforeEach
    public void setup() {
        factory = HashFactory.getInstance();
    }

    @Test
    public void defineRealHashAlgorithmName_forHashName() {
        String algorithmName = factory.defineRealHashAlgorithmName("SHA-256");
        assertThat(algorithmName).isEqualTo("SHA-256");
    }

    @Test
    public void defineRealHashAlgorithmName_forKeyName() {
        String algorithmName = factory.defineRealHashAlgorithmName("PBKDF2");

        String expected = defineExpectedName();
        assertThat(algorithmName).isEqualTo(expected);
    }

    @Test
    public void defineRealHashAlgorithmName_other() {
        Assertions.assertThrows(ConfigurationException.class, () -> factory.defineRealHashAlgorithmName("other"));
    }

    @Test
    public void defineHash_forHashName() {
        factory.defineRealHashAlgorithmName("SHA-256"); // required to correctly initialize factory
        Hash hash = factory.defineHash("SHA-256", "password", "salt", 1);
        assertThat(hash).isExactlyInstanceOf(Hash.class);  // Check if we do not have a SecretKeyHash
        assertThat(hash.toHex()).isEqualToIgnoringCase("13601bda4ea78e55a07b98866d2be6be0744e3866f13c00c811cab608a28f322");

    }

    @Test
    public void defineHash_forHashName_usingByteSource() {
        factory.defineRealHashAlgorithmName("SHA-256"); // required to correctly initialize factory
        Hash hash = factory.defineHash("SHA-256", "password", ByteSource.creator.bytes("salt"), 1);
        assertThat(hash).isExactlyInstanceOf(Hash.class);  // Check if we do not have a SecretKeyHash
        assertThat(hash.toHex()).isEqualToIgnoringCase("13601bda4ea78e55a07b98866d2be6be0744e3866f13c00c811cab608a28f322");

    }

    @Test
    public void defineHash_forHashName_wrongSaltType() {
        factory.defineRealHashAlgorithmName("SHA-256"); // required to correctly initialize factory
        Assertions.assertThrows(CodecException.class, () -> factory.defineHash("SHA-256", "password", 15L, 1));

    }

    @Test
    public void defineHash_forHashName_noSalt() {
        factory.defineRealHashAlgorithmName("SHA-256"); // required to correctly initialize factory
        Hash hash = factory.defineHash("SHA-256", "password", null, 1);
        assertThat(hash).isExactlyInstanceOf(Hash.class);  // Check if we do not have a SecretKeyHash
        assertThat(hash.toHex()).isEqualToIgnoringCase("5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8");

    }

    @Test
    public void defineHash_forHashName_emptySalt() {
        factory.defineRealHashAlgorithmName("SHA-256"); // required to correctly initialize factory
        Hash hash = factory.defineHash("SHA-256", "password", new byte[]{}, 1);
        assertThat(hash).isExactlyInstanceOf(Hash.class);  // Check if we do not have a SecretKeyHash
        assertThat(hash.toHex()).isEqualToIgnoringCase("5E884898DA28047151D0E56F8DC6292773603D0D6AABBDD62A11EF721D1542D8");
    }

    @Test
    public void defineHash_forKeyName() {
        factory.defineRealHashAlgorithmName("PBKDF2"); // required to correctly initialize factory
        Hash hash = factory.defineHash("PBKDF2", "password", "salt", 1);
        assertThat(hash).isExactlyInstanceOf(SecretKeyHash.class);
        assertThat(hash.toHex()).isEqualToIgnoringCase("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    }

    @Test
    public void defineHash_forKeyName_noSalt() {
        factory.defineRealHashAlgorithmName("PBKDF2"); // required to correctly initialize factory

        Assertions.assertThrows(MissingSaltException.class, () -> factory.defineHash("PBKDF2", "password", null, 1));

    }

    @Test
    public void defineHash_forKeyName_emptySalt() {
        factory.defineRealHashAlgorithmName("PBKDF2"); // required to correctly initialize factory
        Assertions.assertThrows(MissingSaltException.class, () -> factory.defineHash("PBKDF2", "password", new byte[]{}, 1));

    }

}