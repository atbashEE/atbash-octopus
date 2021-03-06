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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 * FIXME Remove the Name Web later on? when this has moved to his own artifact.
 *  singleSession and singleLogout are typical for JSF (I don't think it is possible to use with Rest)
 *  But they are here since ActiveSessionRegistry/LogoutHandler is in common-web. Maybe that needs to be moved to JSF.
 */
@ApplicationScoped
@ModuleConfigName("Octopus Web Configuration")
public class OctopusWebConfiguration implements ModuleConfig {

    @Inject
    @ConfigProperty(name = "securedURLs.file", defaultValue = "/WEB-INF/securedURLs.ini")
    private String securedURLsFile;

    @Inject
    @ConfigProperty(name = "single.session", defaultValue = "false")
    private boolean singleSession;

    @Inject
    @ConfigProperty(name = "globalAuditActive", defaultValue = "false")
    private boolean globalAuditActive;

    @Inject
    @ConfigProperty(name = "session.invalidate.login", defaultValue = "true")
    private boolean invalidateSessionAtLogin;

    @ConfigEntry
    public String getLocationSecuredURLProperties() {
        return securedURLsFile;
    }

    @ConfigEntry
    public boolean isSingleSession() {
        return singleSession;
    }

    @ConfigEntry
    public boolean isGlobalAuditActive() {
        return globalAuditActive;
    }

    @ConfigProperty
    public boolean getIsSessionInvalidatedAtLogin() {
        return invalidateSessionAtLogin;
    }
}
