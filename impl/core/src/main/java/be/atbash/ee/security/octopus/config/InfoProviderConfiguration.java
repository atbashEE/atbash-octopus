/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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

import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.util.StringUtils;
import be.atbash.ee.security.octopus.util.reflection.ClassUtils;

import java.util.ArrayList;
import java.util.List;

/**
 *
 */

public class InfoProviderConfiguration extends AbstractConfiguration {

    public List<AuthenticationInfoProvider> getAuthenticationInfoProviders() {
        String providerClasses = getOptionalValue("authenticationInfoProvider.class", "", String.class);

        if (!StringUtils.hasText(providerClasses)) {
            // It can be empty as it also loaded by the ServiceLoader mechanism
            return new ArrayList<>();
        }

        List<AuthenticationInfoProvider> result = new ArrayList<>();

        String[] classes = StringUtils.tokenizeToStringArray(StringUtils.clean(providerClasses), ",");
        for (String aClass : classes) {
            result.add((AuthenticationInfoProvider) ClassUtils.newInstance(aClass));
        }

        return result;
    }
}
