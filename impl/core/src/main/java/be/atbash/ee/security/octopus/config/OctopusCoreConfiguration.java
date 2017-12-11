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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.ee.security.octopus.crypto.hash.HashEncoding;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class OctopusCoreConfiguration extends AbstractConfiguration implements ModuleConfig {

    @ConfigEntry
    public String getHashAlgorithmName() {
        return getOptionalValue("hashAlgorithmName", "", String.class);
    }

    @ConfigEntry
    public HashEncoding getHashEncoding() {
        String hashEncoding = getOptionalValue("hashEncoding", HashEncoding.HEX.name(), String.class);

        HashEncoding result = HashEncoding.fromValue(hashEncoding);
        if (result == null) {
            throw new ConfigurationException(
                    String.format("The 'hashEncoding' parameter value %s isn't valid. Use 'HEX' or 'BASE64'.", hashEncoding));
        }
        return result;
    }

    @ConfigEntry
    public int getSaltLength() {
        // FIXME Validation. Warn if less then 16 (other then 0 of course).
        return getOptionalValue("saltLength", 0, Integer.class);
    }

}
