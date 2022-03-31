/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.mp.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.config.logging.StartupLogging;
import be.atbash.util.CDICheck;

import jakarta.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus MicroProfile JWT Configuration (Rest Client)")
public class MPRestClientConfiguration extends AbstractConfiguration implements ModuleConfig {

    @ConfigEntry
    public String getKeyId() {
        return getOptionalValue("mp.key.id", String.class);
    }

    // Java SE Support
    private static MPRestClientConfiguration INSTANCE;

    private static final Object LOCK = new Object();

    public static MPRestClientConfiguration getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new MPRestClientConfiguration();
                    if (!CDICheck.withinContainer()) {
                        StartupLogging.logConfiguration(INSTANCE);
                    }
                }
            }
        }
        return INSTANCE;
    }

}
