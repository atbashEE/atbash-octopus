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
package be.atbash.ee.security.octopus.oauth2.config;

import be.atbash.util.CDIUtils;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class ProviderSelection {

    // This will keep track of which OAuth2 provider will be used
    // From JSF -> It will be set by OAuth2ServletInfo
    private ThreadLocal<String> providerSelection;

    public String getProvider() {
        String result = providerSelection.get();
        if (result == null) {
            UserProviderSelection userProviderSelection = CDIUtils.retrieveOptionalInstance(UserProviderSelection.class);
            if (userProviderSelection != null) {
                result = userProviderSelection.getSelection();
            }
        }
        return result;
    }
}
