/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.token;

import be.atbash.util.Reviewed;
import be.atbash.util.exception.AtbashUnexpectedException;
import oshi.SystemInfo;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Generates a secret (byte array) usable as HMAC signing of a JWT which is linked to some Hardware identification of the machine and a passPhrase from the user.
 * This makes it possible to generate a JWT where the signing is linked to the machine and thus only verifiable on the same machine.
 */
@Reviewed
public final class LocalSecretFactory {

    private LocalSecretFactory() {
    }

    /**
     * Byte array generated using PBKDF key derivation with passPhrase as key and the hardware info as salt.
     *
     * @param passPhrase
     * @return
     */
    public static byte[] generateSecret(String passPhrase) {
        SystemInfo info = new SystemInfo();
        String salt = info.getHardware().getProcessor().getProcessorID() + info.getOperatingSystem().getFileSystem().getFileStores()[0].getUUID();

        byte[] secret;
        try {
            secret = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(
                    new PBEKeySpec(passPhrase.toCharArray(), salt.getBytes(), 1024, 256)).getEncoded();
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new AtbashUnexpectedException(e);
        }

        return secret;
    }
}
