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
package be.atbash.ee.security.octopus.crypto;

import be.atbash.util.codec.ByteSource;
import be.atbash.util.codec.CodecSupport;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;

import static org.assertj.core.api.Assertions.assertThat;

@Disabled
public class AESCipherServiceTest {

    private String[] PLAINTEXTS = new String[]{
            "Hello, this is a test.",
            "Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
    };

    private AESCipherService cipherService;

    @BeforeEach
    public void setup() {
        cipherService = new AESCipherService();
    }

    //@Test
    @Disabled // FIXME tests fails on Maven
    public void testCycle() {
        byte[] key = cipherService.generateNewKey().getEncoded();

        for (String plain : PLAINTEXTS) {
            byte[] plaintext = CodecSupport.toBytes(plain);
            ByteSource cipherText = cipherService.encrypt(plaintext, key);
            ByteSource decrypted = cipherService.decrypt(cipherText.getBytes(), key);
            assertThat(plaintext).isEqualTo(decrypted.getBytes());
        }
    }

    //@Test
    @Disabled // FIXME tests fails on Maven
    public void testWrongKeys() {
        byte[] key1 = cipherService.generateNewKey().getEncoded();
        byte[] key2 = cipherService.generateNewKey().getEncoded();


        byte[] plaintext = CodecSupport.toBytes(PLAINTEXTS[0]);
        ByteSource cipherText = cipherService.encrypt(plaintext, key1);
        Assertions.assertThrows(CryptoException.class, () -> cipherService.decrypt(cipherText.getBytes(), key2));
    }
}