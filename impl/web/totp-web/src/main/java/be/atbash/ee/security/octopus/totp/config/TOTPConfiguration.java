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
package be.atbash.ee.security.octopus.totp.config;

import be.atbash.config.logging.ConfigEntry;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.otp.config.OTPConfiguration;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Specializes;

@Specializes
@ApplicationScoped
public class TOTPConfiguration extends OTPConfiguration {

    @ConfigEntry
    @Override
    public String getOTPProvider() {
        return getOptionalValue("otp.provider", "TOTP", String.class);
    }

    @ConfigEntry
    public int getWindow() {
        int result;
        try {
            result = Integer.parseInt(getOptionalValue("totp.window", "1", String.class));
        } catch (NumberFormatException e) {
            throw new ConfigurationException("totp.window property must be numeric (Integer)");
        }
        return result;
    }
}
