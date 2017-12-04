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
package be.atbash.ee.security.octopus.crypto.hash;

import be.atbash.ee.security.octopus.config.OctopusWebConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.security.SecureRandom;

@ApplicationScoped
public class SaltHashingUtil {

    private static final Logger LOGGER = LoggerFactory.getLogger(SaltHashingUtil.class);

    private int saltLength;

    @Inject
    private OctopusWebConfiguration config;

    @PostConstruct
    public void init() {
        saltLength = config.getSaltLength();
    }

    public byte[] nextSalt() {
        byte[] salt = new byte[saltLength];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(salt);
        return salt;
    }

    public String hash(String password, byte[] salt) {
        HashEncoding hashEncoding = config.getHashEncoding();

        String result;
        switch (hashEncoding) {

            case HEX:
                result = hashInHex(password, salt);
                break;
            case BASE64:
                result = hashInBase64(password, salt);
                break;
            default:
                throw new IllegalArgumentException("hashEncoding " + hashEncoding + " not supported");
        }
        return result;
    }

    public String hashInHex(String password, byte[] salt) {
        SimpleHash hash = new SimpleHash(config.getHashAlgorithmName(), password, salt);
        return hash.toHex();
    }

    public String hashInBase64(String password, byte[] salt) {
        SimpleHash hash = new SimpleHash(config.getHashAlgorithmName(), password, salt);
        return hash.toBase64();
    }

}
