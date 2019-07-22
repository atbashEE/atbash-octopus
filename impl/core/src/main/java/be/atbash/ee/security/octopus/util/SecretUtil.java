/*
 * Copyright 2014-2017 Rudy De Busscher (www.c4j.be)
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
package be.atbash.ee.security.octopus.util;

import be.atbash.util.PublicAPI;
import be.atbash.util.base64.Base64Codec;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.security.SecureRandom;

/**
 * Generates a random byte array and codes as Base64.
 */
@PublicAPI
@ApplicationScoped
public class SecretUtil {

    private SecureRandom secureRandom;

    @PostConstruct
    public void init() {
        secureRandom = new SecureRandom();
    }

    public String generateSecretBase64(int byteLength) {
        if (byteLength < 1) {
            throw new IllegalArgumentException("'byteLength' parameters must be at least 1");
        }
        byte[] secret = new byte[byteLength];

        secureRandom.nextBytes(secret);
        return Base64Codec.encodeToString(secret, true);
    }

    // Java SE Support + Used in CDI Extension
    private static SecretUtil INSTANCE;

    private static final Object LOCK = new Object();

    public static SecretUtil getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new SecretUtil();
                    INSTANCE.init();
                }
            }
        }
        return INSTANCE;
    }

}
