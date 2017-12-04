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
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 * TODO Remove the Name Web later on? when this has moved to his own artifact.
 */
@ApplicationScoped
public class OctopusWebConfiguration implements ModuleConfig {

    @Inject
    @ConfigProperty(name = "securedURLs.file", defaultValue = "/WEB-INF/securedURLs.ini")
    private String securedURLsFile;

    @Inject
    @ConfigProperty(name = "hashAlgorithmName", defaultValue = "")
    private String hashAlgorithmName;

    @Inject
    @ConfigProperty(name = "hashEncoding", defaultValue = "HEX")
    private String hashEncoding;

    @Inject
    @ConfigProperty(name = "saltLength", defaultValue = "0")
    private int saltLength;

    @ConfigEntry
    public String getLocationSecuredURLProperties() {
        return securedURLsFile;
    }

    @ConfigEntry
    public String getHashAlgorithmName() {
        return hashAlgorithmName;
    }

    @ConfigEntry
    public HashEncoding getHashEncoding() {
        HashEncoding result = HashEncoding.fromValue(hashEncoding);
        if (result == null) {
            throw new ConfigurationException(
                    String.format("The 'hashEncoding' parameter value %s isn't valid. Use 'HEX' or 'BASE64'.", hashEncoding));
        }
        return result;
    }

    @ConfigEntry
    public int getSaltLength() {
        return saltLength;  // FIXME Validation. Warn if less then 16.
    }

}
