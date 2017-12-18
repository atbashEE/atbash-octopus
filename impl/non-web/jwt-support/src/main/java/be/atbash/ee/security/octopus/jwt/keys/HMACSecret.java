/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.jwt.keys;

import be.atbash.ee.security.octopus.util.Base64Codec;
import be.atbash.ee.security.octopus.util.StringUtils;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.SecretJWK;
import com.nimbusds.jose.util.ByteUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.util.LinkedHashMap;
import java.util.Objects;

/**
 * Easier then OctetSequenceKey?
 */

public class HMACSecret extends JWK implements SecretJWK {

    private byte[] secret;

    public HMACSecret(byte[] secret, String id) {
        super(KeyType.OCT, KeyUse.SIGNATURE, null, new Algorithm("HMAC"), id, null, null, null, null, null);
        if (!StringUtils.hasText(id)) {
            throw new IllegalArgumentException("Parameter id should have a value");
        }
        this.secret = Objects.requireNonNull(secret, "Parameter secret should not be null");
    }

    public HMACSecret(String secret, String id, boolean base64Encode) {
        super(KeyType.OCT, KeyUse.SIGNATURE, null, new Algorithm("HMAC"), id, null, null, null, null, null);
        if (!StringUtils.hasText(id)) {
            throw new IllegalArgumentException("Parameter id should have a value");
        }
        if (!StringUtils.hasText(id)) {
            throw new IllegalArgumentException("Parameter secret should have a value");
        }
        if (base64Encode) {
            this.secret = Base64Codec.decode(secret);
        } else {
            this.secret = secret.getBytes(Charset.forName("UTF-8"));
        }
    }

    @Override
    public LinkedHashMap<String, ?> getRequiredParams() {
        return new LinkedHashMap<>();
    }

    @Override
    public boolean isPrivate() {
        // FIXME default value, where do we use this?
        return false;
    }

    @Override
    public JWK toPublicJWK() {
        throw new UnsupportedOperationException("Method not implemented be.atbash.ee.security.octopus.jwt.keys.HMACSecret.toPublicJWK");

    }

    @Override
    public int size() {
        return ByteUtils.bitLength(secret);
    }

    @Override
    public SecretKey toSecretKey() {
        return new SecretKeySpec(secret, getAlgorithm().getName());
    }
}
