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
package be.atbash.ee.security.octopus.crypto.hash;

import be.atbash.ee.security.octopus.crypto.MissingSaltException;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 *
 */

public class SecretKeyHash extends Hash {

    public SecretKeyHash(String keyFactoryName, Object credentials, Object salt, int hashIterations) {
        super(keyFactoryName, credentials, salt, hashIterations);
    }

    @Override
    protected byte[] hash(byte[] bytes, byte[] salt, int hashIterations) {

        if (salt == null || salt.length == 0) {
            throw new MissingSaltException();
        }
        String keySecretName = HashFactory.getInstance().defineRealHashAlgorithmName(getAlgorithmName());
        SecretKeyFactory keyFactory;
        try {
            keyFactory = SecretKeyFactory.getInstance(keySecretName);
        } catch (NoSuchAlgorithmException e) {
            throw new AtbashUnexpectedException(e);
        }

        int keySizeBytes = 32; // TODO Config or calculated (should be related to the SHA version in use.)

        String text = new String(bytes, StandardCharsets.UTF_8);
        char[] chars = text.toCharArray();

        byte[] encoded;
        try {
            encoded = keyFactory.generateSecret(
                    new PBEKeySpec(chars, salt, hashIterations, keySizeBytes * 8)).getEncoded();
        } catch (InvalidKeySpecException e) {
            throw new AtbashUnexpectedException(e);
        }
        return encoded;
    }

}
