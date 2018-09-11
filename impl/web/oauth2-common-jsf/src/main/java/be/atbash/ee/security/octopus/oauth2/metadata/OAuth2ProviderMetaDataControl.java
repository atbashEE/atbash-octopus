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
package be.atbash.ee.security.octopus.oauth2.metadata;

import be.atbash.util.CDIUtils;
import be.atbash.util.exception.AtbashIllegalActionException;
import be.atbash.util.exception.AtbashUnexpectedException;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class OAuth2ProviderMetaDataControl {

    private List<OAuth2ProviderMetaData> providerInfos;

    @PostConstruct
    public void init() {
        providerInfos = CDIUtils.retrieveInstances(OAuth2ProviderMetaData.class);
    }

    public List<OAuth2ProviderMetaData> getProviderInfos() {
        return providerInfos;
    }

    public OAuth2ProviderMetaData getProviderMetaData(String provider) {
        OAuth2ProviderMetaData result = null;
        for (OAuth2ProviderMetaData providerInfo : providerInfos) {
            if (providerInfo.getName().equals(provider)) {
                result = providerInfo;
            }
        }
        if (result == null) {
            // Should never happen, but block it here for the rest of the code chain.
            throw new AtbashUnexpectedException(String.format("Provider not found %s", provider));
        }
        return result;
    }

    public OAuth2ProviderMetaData getSingleProviderMetaData() {
        if (providerInfos.size() != 1) {
            throw new AtbashIllegalActionException(String.format("Method can only be called when exactly 1 OAuth2 provider is available. Found %s", getProviderNames()));
        }

        return providerInfos.get(0);
    }

    private String getProviderNames() {
        StringBuilder result = new StringBuilder();
        for (OAuth2ProviderMetaData providerInfo : providerInfos) {
            if (result.length() > 1) {
                result.append(" - ");
            }
            result.append(providerInfo.getName());
        }
        return result.toString();
    }
}