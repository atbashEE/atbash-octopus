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
package be.atbash.ee.security.octopus.oauth2.config;

import be.atbash.config.AbstractConfiguration;
import be.atbash.config.logging.ConfigEntry;
import be.atbash.config.logging.ModuleConfig;
import be.atbash.config.logging.ModuleConfigName;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2Provider;
import be.atbash.ee.security.octopus.oauth2.metadata.OAuth2ProviderControl;
import be.atbash.util.Reviewed;
import be.atbash.util.StringUtils;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 *
 */
@ApplicationScoped
@ModuleConfigName("Octopus OAuth2 Common Configuration")
@Reviewed
public class OAuth2Configuration extends AbstractConfiguration implements ModuleConfig {

    @Inject
    private OAuth2ProviderControl oAuth2ProviderMetaDataControl;

    @Inject
    private ProviderSelection providerSelection;

    @ConfigEntry(noLogging = true)
    public String getClientId() {
        String result = defineConfigValue("OAuth2.clientId");
        if (StringUtils.isEmpty(result)) {
            throw new ConfigurationException("(???) Parameter value OAuth2.clientId can't be null");
        }
        return result;
    }

    private String defineConfigValue(String configParameter) {
        StringBuilder result = new StringBuilder();
        if (oAuth2ProviderMetaDataControl.getProviderInfos().size() < 2) {
            String configValue = getOptionalValue(configParameter, String.class);
            if (StringUtils.isEmpty(configValue)) {
                configValue = getConfigValueProviderSpecific(configParameter, oAuth2ProviderMetaDataControl.getSingleProviderMetaData().getName());
            }
            if (configValue != null) {
                result.append(configValue);
            }
        } else {
            String userProviderSelection = providerSelection.getProvider();
            if (StringUtils.isEmpty(userProviderSelection)) {
                for (OAuth2Provider oAuth2ProviderMetaData : oAuth2ProviderMetaDataControl.getProviderInfos()) {
                    result.append(oAuth2ProviderMetaData.getName()).append(" : ");
                    result.append(getConfigValueProviderSpecific(configParameter, oAuth2ProviderMetaData.getName()));
                    result.append("\n");
                }
            } else {
                result.append(getConfigValueProviderSpecific(configParameter, userProviderSelection));
            }
        }
        return result.toString();
    }

    private String getConfigValueProviderSpecific(String configParameter, String providerName) {
        return getOptionalValue(providerName + '.' + configParameter, String.class);
    }

    @ConfigEntry(noLogging = true)
    public String getClientSecret() {
        String result = defineConfigValue("OAuth2.clientSecret");
        if (StringUtils.isEmpty(result)) {
            throw new ConfigurationException("(???) Parameter value OAuth2.clientSecret can't be null");
        }
        return result;
    }

    @ConfigEntry
    public String getOAuth2Scopes() {
        return getOptionalValue("OAuth2.scopes", "", String.class);
    }

}
