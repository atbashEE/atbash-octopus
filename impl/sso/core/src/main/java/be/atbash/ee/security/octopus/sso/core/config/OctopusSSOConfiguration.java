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
package be.atbash.ee.security.octopus.sso.core.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.util.PublicAPI;

import jakarta.enterprise.context.ApplicationScoped;

/**
 * Only for the Server, but since OctopusSSOUserConverter is here in sso-core, we need to have another config.
 * TODO verify above comment
 */
@ApplicationScoped
@ModuleConfigName("Octopus SSO Core Configuration")

@PublicAPI
public class OctopusSSOConfiguration extends AbstractConfiguration implements ModuleConfig {

    @ConfigEntry
    public String getKeysToFilter() {
        return getOptionalValue("SSO.user.info.filtered", "", String.class);
    }

}
