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
package be.atbash.ee.security.octopus.rest.client;

import be.atbash.ee.security.octopus.rest.client.config.RestClientProviderConfiguration;
import be.atbash.util.reflection.ClassUtils;
import org.eclipse.microprofile.rest.client.RestClientBuilder;
import org.eclipse.microprofile.rest.client.spi.RestClientBuilderListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 *
 */

public class OctopusRestClientBuilderListener implements RestClientBuilderListener {

    private Logger logger;

    private Map<String, String> defaultMapping;

    public OctopusRestClientBuilderListener() {
        logger = LoggerFactory.getLogger(OctopusRestClientBuilderListener.class);

        defaultMapping = new HashMap<>();
        defaultMapping.put("mp-authc", "be.atbash.ee.security.octopus.mp.rest.MPRestClientProvider");
        defaultMapping.put("keycloak-authc", "be.atbash.ee.security.octopus.keycloak.rest.KeycloakRestClientProvider");
    }

    @Override
    public void onNewBuilder(RestClientBuilder restClientBuilder) {
        String classes = RestClientProviderConfiguration.getInstance().getRestClientProviderClasses();
        String[] providerClasses = classes.split(",");
        if (providerClasses.length > 0) {
            for (String providerClass : providerClasses) {
                String realProviderClassName = getRealProviderClassName(providerClass);
                if (ClassUtils.isAvailable(realProviderClassName)) {
                    restClientBuilder.register(ClassUtils.forName(realProviderClassName));
                } else {
                    // TODO Should this be an error/exception?
                    logger.warn(String.format("Rest Client Provider '%s' not found.", getProviderOutputName(providerClass, realProviderClassName)));
                }
            }
        }
    }

    private String getProviderOutputName(String providerClass, String realProviderClassName) {
        String result = providerClass;
        if (!providerClass.equals(realProviderClassName)) {
            result = providerClass + " (" + realProviderClassName + ")";
        }
        return result;
    }

    private String getRealProviderClassName(String providerClass) {
        String result = providerClass;
        if (defaultMapping.containsKey(providerClass)) {
            result = defaultMapping.get(providerClass); // convert 'shortcut' class names.
        }
        return result;
    }
}
