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

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Generates mapping between the 'simple' name (like PBKDF2) and the actual name used by the JDK like PBKDF2WithHmacSHA1
 * which is Java Version specific.
 * For all names which are not supported (no mapping defined), the name is returned as is.
 */
class KeyFactoryNameFactory {

    private static String JAVA_VERSION = Runtime.class.getPackage().getSpecificationVersion();
    private static KeyFactoryNameFactory INSTANCE;

    private Map<String, Map<String, String>> defaultKeyFactoryNames;

    private KeyFactoryNameFactory() {
        defaultKeyFactoryNames = new HashMap<>();
        definePBKDF2Names();
    }

    private void definePBKDF2Names() {
        Map<String, String> mapping = new HashMap<>();

        mapping.put("1.7", "PBKDF2WithHmacSHA1");
        mapping.put("1.8", "PBKDF2WithHmacSHA256");
        // FIXME Support for Java 9+ (probably will only support 11)

        defaultKeyFactoryNames.put("PBKDF2", mapping);
    }

    /**
     * Returns the actual name for the Key derivation function, like PBKDF2WithHmacSHA1 or the parameter itself when no
     * mapping is defined.
     *
     * @param name The name for which we need the Java Version specific name.
     * @return The name of the Key derivation function for this Java Version.
     */
    String getKeyFactoryName(String name) {
        String nameUpperCase = name.toUpperCase(Locale.ENGLISH);
        String result;

        if (defaultKeyFactoryNames.containsKey(nameUpperCase)) {
            result = defaultKeyFactoryNames.get(nameUpperCase).get(JAVA_VERSION);
        } else {
            result = name;
        }
        return result;
    }

    static KeyFactoryNameFactory getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new KeyFactoryNameFactory();
        }
        return INSTANCE;
    }
}
