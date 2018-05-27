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
package be.atbash.ee.security.octopus;

import be.atbash.util.base64.Base64Codec;
import oshi.SystemInfo;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * Generates The local secret based on the passphrase.
 */

public class LocalSecret {

    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // TODO This code is demo as the passphrase is hardcoded.
        SystemInfo info = new SystemInfo();
        String salt = info.getHardware().getProcessor().getProcessorID() + info.getOperatingSystem().getFileSystem().getFileStores()[0].getUUID();

        String passPhrase = "Rudy";

        // PBKDF2WithHmacSHA1 available on Java 7 and Java 8. Must match value used on LocalSecretFactory.
        // TODO possible usage scenario. using this local secret, the end user can create the OfflineToken with a Web application (where he needs to authenticate himself
        // in order to create a correct OfflineToken instance for the user.
        byte[] secret = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1").generateSecret(
                new PBEKeySpec(passPhrase.toCharArray(), salt.getBytes(), 1024, 256)).getEncoded();

        String secret64 = Base64Codec.encodeToString(secret, true);
        System.out.println("Local secret value is " + secret64);

    }
}
