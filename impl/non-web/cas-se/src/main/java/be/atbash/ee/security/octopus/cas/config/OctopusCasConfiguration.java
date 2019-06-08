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
package be.atbash.ee.security.octopus.cas.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.config.logging.StartupLogging;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.util.StringUtils;
import be.atbash.util.reflection.CDICheck;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus Keycloak Configuration")
public class OctopusCasConfiguration extends AbstractConfiguration implements ModuleConfig {

    private String casService;

    @ConfigEntry
    public String getCASEmailProperty() {
        return getOptionalValue("CAS.property.email", "email", String.class);
    }

    @ConfigEntry
    public String getSSOServer() {
        // FIXME Also support SSO.server. Make same as KeyCloak (verify)
        String result = getOptionalValue("CAS.SSO.server", String.class);
        if (StringUtils.isEmpty(result)) {
            throw new ConfigurationException("A value for 'CAS.SSO.server' is required.");
        }
        return result;
    }

    @ConfigEntry
    public CASProtocol getCASProtocol() {

        String casProtocol = getOptionalValue("CAS.protocol", "CAS", String.class);

        // SAML should also be supported, but not tested for the moment.

        CASProtocol result = CASProtocol.fromValue(casProtocol);
        if (result == null) {
            throw new ConfigurationException(String.format("Invalid value for parameter CAS.protocol specified : %s (CAS or SAML allowed)", casProtocol));
        }
        return result;
    }

    @ConfigEntry
    public String getCASService() {
        if (casService == null) {
            casService = getOptionalValue("CAS.service", String.class);
        }
        return casService;
    }

    public void setCasService(String casService) {
        this.casService = casService;
    }

    // Java SE Support
    private static OctopusCasConfiguration INSTANCE;

    private static final Object LOCK = new Object();

    public static OctopusCasConfiguration getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new OctopusCasConfiguration();
                    if (!CDICheck.withinContainer()) {
                        StartupLogging.logConfiguration(INSTANCE);
                    }
                }
            }
        }
        return INSTANCE;
    }

}
