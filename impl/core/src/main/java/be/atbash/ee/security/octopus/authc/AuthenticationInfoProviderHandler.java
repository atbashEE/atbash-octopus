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
package be.atbash.ee.security.octopus.authc;

import be.atbash.ee.security.octopus.config.InfoProviderConfiguration;
import be.atbash.ee.security.octopus.realm.RealmConfigurationException;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.AnnotationUtil;
import be.atbash.ee.security.octopus.util.order.ProviderComparator;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.ServiceLoader;

/**
 * FIXME, just uses the first provider it finds.
 */
@ApplicationScoped
public class AuthenticationInfoProviderHandler {

    @Inject
    private Instance<AuthenticationInfoProvider> authenticationInfoProviderInstances;

    private List<AuthenticationInfoProvider> authenticationInfoProviders;

    private AuthenticationStrategyValue authenticationStrategyValue;

    @PostConstruct
    public void init() {
        retrieveProviders();

        Collections.sort(authenticationInfoProviders, new ProviderComparator());

        defineStrategy();
    }

    private void defineStrategy() {
        for (AuthenticationInfoProvider authenticationInfoProvider : authenticationInfoProviders) {
            AuthenticationStrategy strategy = AnnotationUtil.getAnnotation(authenticationInfoProvider.getClass(), AuthenticationStrategy.class);
            // FIXME
        }
    }

    private void retrieveProviders() {
        authenticationInfoProviders = new ArrayList<>();
        if (!authenticationInfoProviderInstances.isUnsatisfied()) {
            for (AuthenticationInfoProvider authenticationInfoProvider : authenticationInfoProviderInstances.select()) {
                authenticationInfoProviders.add(authenticationInfoProvider);
            }
        }

        if (authenticationInfoProviders.isEmpty()) {
            throw new RealmConfigurationException("Missing implementation as CDI bean of SecurityDataProvider or AuthenticationInfoProvider");
        }
    }

    public AuthenticationInfo retrieveAuthenticationInfo(AuthenticationToken token) {
        prepareAuthenticationInfoProviders();

        // FIXME
        return authenticationInfoProviders.get(0).getAuthenticationInfo(token);
    }

    private void prepareAuthenticationInfoProviders() {
        if (authenticationInfoProviders == null) {
            // From configuration, Developer defined.
            InfoProviderConfiguration config = new InfoProviderConfiguration();
            authenticationInfoProviders = config.getAuthenticationInfoProviders();

            // From the Octopus modules.
            ServiceLoader<AuthenticationInfoProvider> providers = ServiceLoader.load(AuthenticationInfoProvider.class);
            for (AuthenticationInfoProvider provider : providers) {
                authenticationInfoProviders.add(provider);
            }

            Collections.sort(authenticationInfoProviders, new ProviderComparator());
        }
    }

}
