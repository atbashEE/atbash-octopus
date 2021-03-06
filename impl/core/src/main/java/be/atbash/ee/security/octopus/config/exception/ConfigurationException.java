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
package be.atbash.ee.security.octopus.config.exception;

import be.atbash.ee.security.octopus.OctopusException;
import be.atbash.ee.security.octopus.ShiroEquivalent;

/**
 * Exception indicating there was a problem parsing or processing the Octopus configuration.
 * Octopus way of using : Only to be used for 'logical' errors, wrong or missing config should be using the ConfigurationException from the Atbash-config
 */
@ShiroEquivalent(shiroClassNames = {"org.apache.shiro.config.ConfigurationException"})
public class ConfigurationException extends OctopusException {

    /**
     * Constructs a new ConfigurationException.
     *
     * @param message the reason for the exception
     */
    public ConfigurationException(String message) {
        super(message);
    }

    /**
     * Constructs a new ConfigurationException.
     *
     * @param message the reason for the exception
     * @param cause   the underlying Throwable that caused this exception to be thrown.
     */
    public ConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
