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
package be.atbash.ee.security.octopus.crypto.hash;

import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.util.PublicAPI;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.SecureRandom;

@ApplicationScoped
@PublicAPI
public class SaltHashingUtil {

    private static SaltHashingUtil INSTANCE;

    private int saltLength;

    private SecureRandom secureRandom;

    @Inject
    private OctopusCoreConfiguration config;

    private HashFactory hashFactory;

    @PostConstruct
    public void init() {
        saltLength = config.getSaltLength();
        hashFactory = HashFactory.getInstance();
        secureRandom = new SecureRandom();
    }

    public byte[] nextSalt() {
        byte[] salt = new byte[saltLength];

        secureRandom.nextBytes(salt);
        return salt;
    }

    public String hash(String password, byte[] salt) {
        HashEncoding hashEncoding = config.getHashEncoding();

        String hashAlgorithmName = hashFactory.defineRealHashAlgorithmName(config.getHashAlgorithmName());
        String result;
        Hash hash = hashFactory.defineHash(hashAlgorithmName, password, salt, saltLength);
        switch (hashEncoding) {

            case HEX:
                result = hash.toHex();
                break;
            case BASE64:
                result = hash.toBase64();
                break;
            default:
                throw new IllegalArgumentException("hashEncoding " + hashEncoding + " not supported");
        }
        return result;
    }

    public static SaltHashingUtil getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new SaltHashingUtil();
            INSTANCE.config = OctopusCoreConfiguration.getInstance();
            INSTANCE.init();
        }
        return INSTANCE;
    }
}
