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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.crypto.AESCipherService;
import be.atbash.util.StringUtils;
import be.atbash.util.base64.Base64Codec;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus RememberMe Configuration")
public class RememberMeConfiguration extends AbstractConfiguration implements ModuleConfig {

    @Inject
    @ConfigProperty(name = "octopus.rememberme.cookie.name", defaultValue = "rememberMe")
    private String cookieName;

    @Inject
    @ConfigProperty(name = "octopus.rememberme.cookie.maxage", defaultValue = "31536000")  // One Year
    private Integer cookieMaxAge;

    @Inject
    @ConfigProperty(name = "octopus.rememberme.cookie.secure", defaultValue = "false")
    // Cookie value is already encrypted
    private boolean cookieSecureOnly;

    private byte[] cipherKey;

    @ConfigEntry()
    public String getCookieName() {
        return cookieName;
    }

    @ConfigEntry()
    public Integer getCookieMaxAge() {
        return cookieMaxAge;
    }

    @ConfigEntry
    public boolean isCookieSecureOnly() {
        return cookieSecureOnly;
    }

    @ConfigEntry
    public byte[] getCipherKey() {
        if (cipherKey == null) {
            String cipherValue = getOptionalValue("octopus.rememberme.cipherkey", "", String.class);
            if (StringUtils.hasText(cipherValue)) {
                if (!Base64Codec.isBase64Encoded(cipherValue)) {
                    throw new ConfigurationException("Value for 'octopus.rememberme.cipherkey' must be a BASE64 encoded byte array");
                }
                cipherKey = Base64Codec.decode(cipherValue);
            } else {
                // FIXME Fix this unhealthy relation
                cipherKey = new AESCipherService().generateNewKey().getEncoded();
            }
        }
        return cipherKey;
    }
}
