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
import be.atbash.ee.security.octopus.util.PeriodUtil;
import be.atbash.util.StringUtils;
import be.atbash.util.reflection.CDICheck;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus MicroProfile JWT Configuration (Core)")
public class MPCoreConfiguration extends AbstractConfiguration implements ModuleConfig {

    @ConfigEntry
    public String getIssuer() {
        return getOptionalValue("mp.iss", String.class);
    }

    @ConfigEntry
    public String getAudience() {
        return getOptionalValue("mp.aud", String.class);
    }

    @ConfigEntry
    public String getExpirationTime() {
        String expirationExpression = getOptionalValue("mp.exp", String.class);
        if (StringUtils.hasText(expirationExpression)) {
            // Validate the expression
            PeriodUtil.defineSecondsInPeriod(expirationExpression);
        }
        return expirationExpression;
    }

    // Java SE Support
    private static MPCoreConfiguration INSTANCE;

    private static final Object LOCK = new Object();

    public static MPCoreConfiguration getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new MPCoreConfiguration();
                    if (!CDICheck.withinContainer()) {
                        StartupLogging.logConfiguration(INSTANCE);
                    }
                }
            }
        }
        return INSTANCE;
    }

}
