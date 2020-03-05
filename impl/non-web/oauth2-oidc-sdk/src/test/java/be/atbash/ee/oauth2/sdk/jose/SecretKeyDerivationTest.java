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
package be.atbash.ee.oauth2.sdk.jose;


import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.security.octopus.nimbus.jose.JOSEException;
import be.atbash.ee.security.octopus.nimbus.jose.Payload;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.AESEncrypter;
import be.atbash.ee.security.octopus.nimbus.jose.crypto.DirectEncrypter;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEHeader;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEObject;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

;


public class SecretKeyDerivationTest {

    private static Secret CLIENT_SECRET = new Secret(ByteUtils.byteLength(256));

    @Test
    public void testDerive_dir_A128GCM()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A128GCM);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(128));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), new Payload("Hello, world!"));
        jwe.encrypt(new DirectEncrypter(key));
    }

    @Test
    public void testDerive_dir_A192GCM()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A192GCM);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(192));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A192GCM), new Payload("Hello, world!"));
        jwe.encrypt(new DirectEncrypter(key));
    }

    @Test
    public void testDerive_dir_A256GCM()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A256GCM);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(256));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM), new Payload("Hello, world!"));
        jwe.encrypt(new DirectEncrypter(key));
    }

    @Test
    public void testDerive_dir_A128CBC_HS256()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(256));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256), new Payload("Hello, world!"));
        jwe.encrypt(new DirectEncrypter(key));
    }

    @Test
    public void testDerive_dir_HS384()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A192CBC_HS384);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(384));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A192CBC_HS384), new Payload("Hello, world!"));
        jwe.encrypt(new DirectEncrypter(key));
    }

    @Test
    public void testDerive_dir_A256CBC_HS512()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(512));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
        jwe.encrypt(new DirectEncrypter(key));
    }

    @Test
    public void testDerive_A128KW()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A128KW, EncryptionMethod.A256CBC_HS512);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(128));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A128KW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
        jwe.encrypt(new AESEncrypter(key));
    }

    @Test
    public void testDerive_A192KW()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A192KW, EncryptionMethod.A256CBC_HS512);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(192));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A192KW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
        jwe.encrypt(new AESEncrypter(key));
    }

    @Test
    public void testDerive_A256KW()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A256KW, EncryptionMethod.A256CBC_HS512);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(256));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A256KW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
        jwe.encrypt(new AESEncrypter(key));
    }

    @Test
    public void testDerive_A128GCMKW()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A128GCMKW, EncryptionMethod.A256CBC_HS512);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(128));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A128GCMKW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
        jwe.encrypt(new AESEncrypter(key));
    }

    @Test
    public void testDerive_A192GCMKW()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A192GCMKW, EncryptionMethod.A256CBC_HS512);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(192));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A192GCMKW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
        jwe.encrypt(new AESEncrypter(key));
    }

    @Test
    public void testDerive_A256GCMKW()
            throws Exception {

        SecretKey key = SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.A256GCMKW, EncryptionMethod.A256CBC_HS512);

        assertThat(key.getAlgorithm()).isEqualTo("AES");
        assertThat(key.getEncoded().length).isEqualTo(ByteUtils.byteLength(256));

        JWEObject jwe = new JWEObject(new JWEHeader(JWEAlgorithm.A256GCMKW, EncryptionMethod.A256CBC_HS512), new Payload("Hello, world!"));
        jwe.encrypt(new AESEncrypter(key));
    }

    @Test
    public void testUnsupportedJWEMethod() {

        try {
            SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, JWEAlgorithm.DIR, new EncryptionMethod("xyz"));
        } catch (JOSEException e) {
            assertThat(e.getMessage()).isEqualTo("Unsupported JWE method: enc=xyz");
        }
    }

    @Test
    public void testUnsupportedSecretKeyLength() {

        try {
            SecretKeyDerivation.deriveSecretKey(CLIENT_SECRET, 1024);
        } catch (JOSEException e) {
            assertThat(e.getMessage()).isEqualTo("Unsupported secret key length: 1024 bits");
        }
    }

    @Test
    public void testMsbTruncate() {

        assertThat(new BigInteger(new byte[]{0, 0, 0, 1}).intValue()).isEqualTo(1);
        assertThat(new BigInteger(new byte[]{1}).intValue()).isEqualTo(1);
    }
}