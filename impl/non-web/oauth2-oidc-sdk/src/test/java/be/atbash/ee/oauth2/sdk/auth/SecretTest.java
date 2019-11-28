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
package be.atbash.ee.oauth2.sdk.auth;


import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the secret / password class.
 */
public class SecretTest {

    @Test
    public void testFullConstructor() {

        Date exp = new Date(new Date().getTime() + 3600 * 1000);
        Secret secret = new Secret("password", exp);
        assertThat(secret.getValue()).isEqualTo("password");
        assertThat(secret.getExpirationDate()).isEqualTo(exp);
        assertThat(secret).isEqualTo(new Secret("password"));
    }

    @Test
    public void testEmptySecret() {

        Secret secret = new Secret("");
        assertThat(secret.getValue()).isEqualTo("");
        assertThat(secret.getValueBytes().length).isEqualTo(0);
    }

    @Test
    public void testErase() {

        Secret secret = new Secret("password");
        assertThat(secret.getValue().length()).isEqualTo("password".length());
        secret.erase();
        assertThat(secret.getValue()).isNull();
    }

    @Test
    public void testNotExpired() {

        Date future = new Date(new Date().getTime() + 3600 * 1000);
        Secret secret = new Secret("password", future);
        assertThat(secret.expired()).isFalse();
    }

    @Test
    public void testExpired() {

        Date past = new Date(new Date().getTime() - 3600 * 1000);
        Secret secret = new Secret("password", past);
        assertThat(secret.expired()).isTrue();
    }

    @Test
    public void testEquality() {

        assertThat(new Secret("password").equals(new Secret("password"))).isTrue();
        assertThat(new Secret("").equals(new Secret(""))).isTrue();

        // Compare erased secrets
        Secret s1 = new Secret("password");
        s1.erase();

        Secret s2 = new Secret("password");
        s2.erase();

        assertThat(s1.equals(s2)).isFalse();

        // Ensure expiration date is ignored in comparison
        Date now = new Date();
        Date tomorrow = new Date(now.getTime() + 24 * 60 * 60 * 1000L);
        assertThat(new Secret("password", tomorrow).equals(new Secret("password", new Date()))).isTrue();
    }

    @Test
    public void testInequality() {

        assertThat(new Secret("password").equals(new Secret("passw0rd"))).isFalse();
        assertThat(new Secret("password").equals(new Secret(""))).isFalse();

        Secret erased = new Secret("password");
        erased.erase();

        assertThat(erased.equals(new Secret("password"))).isFalse();
    }

    @Test
    public void testGenerateDefault() {

        Secret secret = new Secret();

        assertThat(secret.getValueBytes().length).isEqualTo(Secret.DEFAULT_BYTE_LENGTH);
    }

    @Test

    public void testGenerate() {

        Secret secret = new Secret(64);

        assertThat(secret.getValueBytes().length).isEqualTo(64);
    }

    @Test
    public void testBase64URLAlphabet() {

        String base64URLAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

        // 100 trials
        for (int i = 0; i < 100; i++) {

            Secret secret = new Secret();

            for (char c : secret.getValue().toCharArray()) {

                assertThat(base64URLAlphabet).contains(c + "");
            }
        }
    }

    @Test
    public void testSHA256()
            throws NoSuchAlgorithmException {

        Secret secret = new Secret();
        byte[] value = secret.getValueBytes();

        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        assertThat(Arrays.equals(sha256.digest(value), secret.getSHA256())).isTrue();

        // Erase value
        secret.erase();
        assertThat(secret.getSHA256()).isNull();
    }

    @Test
    public void testEqualsSHA256() {

        Secret secret = new Secret();
        Secret anotherSecret = new Secret(Base64URLValue.encode(secret.getValueBytes()));

        assertThat(secret.equals(anotherSecret)).isTrue();

        assertThat(secret.equalsSHA256Based(anotherSecret)).isTrue();

        secret.erase();
        assertThat(secret.equalsSHA256Based(anotherSecret)).isFalse();

        anotherSecret.erase();
        assertThat(secret.equalsSHA256Based(anotherSecret)).isFalse();

        assertThat(secret.equalsSHA256Based(null)).isFalse();
    }

    @Test
    public void testStringValue() {
        String value = "NotSoGoodSecret1234";
        Secret secret = new Secret(value);
        assertThat(secret.getValue()).isEqualTo(value);
        assertThat(secret.getValueBytes()).isEqualTo(value.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    public void testBase64Value()  {
        byte[] key = new byte[32];
        new Random().nextBytes(key);
        Base64URLValue value = Base64URLValue.encode(key);
        Secret secret = new Secret(value);
        assertThat(secret.getValue()).isEqualTo(value.toString());
        assertThat(secret.getValueBytes()).isEqualTo(key);
    }
}
