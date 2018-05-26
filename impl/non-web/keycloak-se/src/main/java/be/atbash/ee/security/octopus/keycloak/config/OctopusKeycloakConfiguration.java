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
package be.atbash.ee.security.octopus.keycloak.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.config.logging.StartupLogging;
import be.atbash.util.StringUtils;
import be.atbash.util.reflection.CDICheck;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus Keycloak Configuration")
public class OctopusKeycloakConfiguration extends AbstractConfiguration implements ModuleConfig {

    @Inject
    @ConfigProperty(name = "keycloak.scopes", defaultValue = "")
    private String scopes;

    @Inject
    @ConfigProperty(name = "keycloak.idpHint", defaultValue = "")
    private String idpHint;

    @ConfigEntry
    public String getLocationKeycloakFile() {
        String propertyValue = getOptionalValue("keycloak.file", "classpath:/keycloak.json", String.class);
        if (StringUtils.isEmpty(propertyValue)) {
            throw new ConfigurationException("keycloak.file configuration property is required");
        }
        return propertyValue;
    }

    @ConfigEntry
    public String getScopes() {
        // TODO use in SE module ?
        return scopes;
    }

    @ConfigEntry
    public String getIdpHint() {
        // TODO use in SE module ?
        // Todo support it in Web
        return idpHint;
    }

    // Java SE Support
    private static OctopusKeycloakConfiguration INSTANCE;

    private static final Object LOCK = new Object();

    public static OctopusKeycloakConfiguration getInstance() {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new OctopusKeycloakConfiguration();
                    if (!CDICheck.withinContainer()) {
                        StartupLogging.logConfiguration(INSTANCE);
                    }
                }
            }
        }
        return INSTANCE;
    }

}
