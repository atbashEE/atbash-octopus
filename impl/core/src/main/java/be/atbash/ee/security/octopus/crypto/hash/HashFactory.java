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

import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.util.PublicAPI;

import javax.crypto.SecretKeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Factory for creating Hashes.
 */
@PublicAPI
public class HashFactory {

    private static HashFactory INSTANCE;

    private KeyFactoryNameFactory factory;
    private Map<String, String> realHashAlgorithmNames;
    private Map<String, HashType> algorithmNameHashTypes;

    private HashFactory() {
        factory = KeyFactoryNameFactory.getInstance();
        realHashAlgorithmNames = new HashMap<>();
        algorithmNameHashTypes = new HashMap<>();
    }

    /**
     * Get an instance of the factory.
     *
     * @return
     */
    public static HashFactory getInstance() {
        // Not synchronized. So in theory we can have the instantiation of more then one. But from that point on, we always use the same one.

        if (INSTANCE == null) {
            INSTANCE = new HashFactory();
        }
        return INSTANCE;
    }

    /**
     * Get the final (mapped) name of the hash algorithm name and verify if the algorithm is supported?
     *
     * @param hashAlgorithmName Algorithm name, generic Key derivation names (like PBKDF2) are supported.
     * @return Supported algorithm name which can be used in the defineHash() method.
     * @throws ConfigurationException when hash algorithm name is not supported.
     */
    public String defineRealHashAlgorithmName(String hashAlgorithmName) {
        // Caching since verifying algorithm names can be a bit time consuming.
        String result = realHashAlgorithmNames.get(hashAlgorithmName);
        if (result != null) {
            return result;
        }
        try {
            MessageDigest.getInstance(hashAlgorithmName);
            result = hashAlgorithmName;
            algorithmNameHashTypes.put(hashAlgorithmName, HashType.HASH);
        } catch (NoSuchAlgorithmException e) {
            String keyFactoryName = factory.getKeyFactoryName(hashAlgorithmName);

            try {
                SecretKeyFactory.getInstance(keyFactoryName); // No assignment -> exception thrown or not is all we need to know.
                result = keyFactoryName;
                algorithmNameHashTypes.put(keyFactoryName, HashType.KEY_FACTORY);
            } catch (NoSuchAlgorithmException e1) {
                throw new ConfigurationException(String.format("Hash algorithm name unknown : %s", hashAlgorithmName));
            }

        }

        realHashAlgorithmNames.put(hashAlgorithmName, result);
        return result;
    }

    /**
     * @param hashAlgorithmName
     * @param source
     * @param salt
     * @param hashIterations
     * @return
     */
    public Hash defineHash(String hashAlgorithmName, Object source, Object salt, int hashIterations) {
        Hash result;

        HashType hashType = algorithmNameHashTypes.get(hashAlgorithmName);
        if (hashType == null) {
            hashType = algorithmNameHashTypes.get(defineRealHashAlgorithmName(hashAlgorithmName));
        }
        switch (hashType) {

            case HASH:
                result = new Hash(hashAlgorithmName, source, salt, hashIterations);
                break;
            case KEY_FACTORY:
                result = new SecretKeyHash(hashAlgorithmName, source, salt, hashIterations);
                break;
            default:
                throw new IllegalArgumentException(String.format("Hash type %s not supported", hashType));
        }
        return result;
    }

    public int getDefaultHashIterations(String hashAlgorithmName) {
        if (algorithmNameHashTypes.get(hashAlgorithmName) == null) {
            defineRealHashAlgorithmName(hashAlgorithmName);
        }
        return algorithmNameHashTypes.get(hashAlgorithmName).defaultHashIterations;
    }

    private enum HashType {
        HASH(1), KEY_FACTORY(1024);

        private int defaultHashIterations;

        HashType(int defaultHashIterations) {
            this.defaultHashIterations = defaultHashIterations;
        }

    }
}
