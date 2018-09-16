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
package be.atbash.ee.security.octopus.oauth2.config.jsf;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2Provider;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderMetaDataControl;
import be.atbash.ee.security.octopus.oauth2.servlet.OAuth2ServletInfo;
import be.atbash.util.CDIUtils;
import be.atbash.util.Reviewed;
import be.atbash.util.StringUtils;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus OAuth2 JSF Configuration")
@Reviewed
public class OAuth2JSFConfiguration extends AbstractConfiguration implements ModuleConfig {

    @ConfigEntry
    public String getOAuth2ProviderSelectionPage() {
        return getOptionalValue("OAuth2.provider.selectionPage", "/login.xhtml", String.class);
    }

    @ConfigEntry
    public boolean getForceGoogleAccountSelection() {
        return getOptionalValue("OAuth2.account.selection", Boolean.FALSE, Boolean.class);
    }

}
