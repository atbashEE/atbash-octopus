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

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

/**
 *
 */

public class AbstractConfiguration {

    protected <T> T getOptionalValue(String key, T defaultValue, Class<T> aClass) {
        Config config = ConfigProvider.getConfig();
        T result = config.getOptionalValue(key, aClass);
        if (result == null) {
            result = defaultValue;
        }
        return result;
    }

    protected <T> T getValue(String key, Class<T> aClass) {
        Config config = ConfigProvider.getConfig();
        return config.getValue(key, aClass);
    }
}
