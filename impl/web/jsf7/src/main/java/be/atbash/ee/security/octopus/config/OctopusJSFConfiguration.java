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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import org.apache.deltaspike.core.api.config.ConfigResolver;
import org.eclipse.microprofile.config.inject.ConfigProperty;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus JSF Configuration")
public class OctopusJSFConfiguration implements ModuleConfig {

    @Inject
    @ConfigProperty(name = "loginPage", defaultValue = "/login.xhtml")
    private String loginPage;

    @Inject
    @ConfigProperty(name = "logoutPage", defaultValue = "/")
    private String logoutPage;

    @Inject
    @ConfigProperty(name = "allowPostAsSavedRequest", defaultValue = "true")
    private boolean allowPostAsSavedRequest;

    @ConfigEntry()
    public String getLoginPage() {
        return loginPage;
    }

    @ConfigEntry
    public String getLogoutPage() {
        return logoutPage;
    }

    @ConfigEntry
    public boolean getPostIsAllowedSavedRequest() {
        return allowPostAsSavedRequest;
    }

    @ConfigEntry
    public String getUnauthorizedExceptionPage() {
        return ConfigResolver.getPropertyValue("unauthorizedExceptionPage", "/unauthorized.xhtml");
    }

    @ConfigEntry
    public String getExcludePrimeFacesMobile() {
        return ConfigResolver.getPropertyValue("primefaces.mobile.exclusion", "false");
    }

}
