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
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.EncryptionMethod;
import be.atbash.ee.security.octopus.nimbus.jwt.jwe.JWEAlgorithm;
import be.atbash.ee.security.octopus.nimbus.util.ByteUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


/**
 * Derives an AES secret key from a client secret. Intended for performing
 * symmetric encryption and decryption with a client secret, as specified in
 * <a href="http://openid.net/specs/openid-connect-core-1_0.html#Encryption">OpenID
 * Connect Core 1.0, section 10.2</a>.
 */
// FIXME Will this be used in Octopus?
public class SecretKeyDerivation {


    /**
     * Derives a secret encryption key from the specified client secret.
     *
     * @param clientSecret The client secret. Must not be {@code null}.
     * @param alg          The JWE algorithm. Must not be {@code null}.
     * @param enc          The JWE method. Must not be {@code null}.
     * @return The matching secret key (with algorithm set to "AES").
     */
    public static SecretKey deriveSecretKey(Secret clientSecret,
                                            JWEAlgorithm alg,
                                            EncryptionMethod enc) {

        if (JWEAlgorithm.DIR.equals(alg)) {

            int cekBitLength = enc.cekBitLength();

            if (cekBitLength == 0) {
                throw new JOSEException("Unsupported JWE method: enc=" + enc);
            }

            return deriveSecretKey(clientSecret, enc.cekBitLength());

        } else if (JWEAlgorithm.Family.AES_KW.contains(alg)) {

            if (JWEAlgorithm.A128KW.equals(alg)) {
                return deriveSecretKey(clientSecret, 128);
            } else if (JWEAlgorithm.A192KW.equals(alg)) {
                return deriveSecretKey(clientSecret, 192);
            } else if (JWEAlgorithm.A256KW.equals(alg)) {
                return deriveSecretKey(clientSecret, 256);
            }

        } else if (JWEAlgorithm.Family.AES_GCM_KW.contains(alg)) {

            if (JWEAlgorithm.A128GCMKW.equals(alg)) {
                return deriveSecretKey(clientSecret, 128);
            } else if (JWEAlgorithm.A192GCMKW.equals(alg)) {
                return deriveSecretKey(clientSecret, 192);
            } else if (JWEAlgorithm.A256GCMKW.equals(alg)) {
                return deriveSecretKey(clientSecret, 256);
            }
        }

        throw new JOSEException("Unsupported JWE algorithm / method: alg=" + alg + " enc=" + enc);
    }


    /**
     * Derives a secret encryption key from the specified client secret.
     *
     * @param clientSecret The client secret. Must not be {@code null}.
     * @param bits         The secret key bits (128, 192, 256, 384 or 512).
     * @return The matching secret key (with algorithm set to "AES").
     */
    public static SecretKey deriveSecretKey(Secret clientSecret, int bits) {

        final int hashBitLength;

        switch (bits) {
            case 128:
            case 192:
            case 256:
                hashBitLength = 256;
                break;
            case 384:
                hashBitLength = 384;
                break;
            case 512:
                hashBitLength = 512;
                break;
            default:
                throw new JOSEException("Unsupported secret key length: " + bits + " bits");
        }

        final byte[] hash;

        try {
            hash = MessageDigest.getInstance("SHA-" + hashBitLength).digest(clientSecret.getValueBytes());

        } catch (NoSuchAlgorithmException e) {
            throw new JOSEException(e.getMessage(), e);
        }

        final byte[] keyBytes;

        // Left-truncate if necessary
        switch (bits) {
            case 128:
                keyBytes = ByteUtils.subArray(hash, ByteUtils.byteLength(256 - 128), ByteUtils.byteLength(128));
                break;
            case 192:
                keyBytes = ByteUtils.subArray(hash, ByteUtils.byteLength(256 - 192), ByteUtils.byteLength(192));
                break;
            case 256:
            case 384:
            case 512:
                keyBytes = hash;
                break;
            default:
                throw new JOSEException("Unsupported secret key length: " + bits + " bits");
        }

        return new SecretKeySpec(keyBytes, "AES");
    }


    /**
     * Prevents public instantiation.
     */
    private SecretKeyDerivation() {
    }
}
