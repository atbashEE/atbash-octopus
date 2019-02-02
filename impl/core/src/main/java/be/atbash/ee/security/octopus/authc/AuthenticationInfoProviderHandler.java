/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
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
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.realm.RealmConfigurationException;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.SystemAuthenticationToken;
import be.atbash.ee.security.octopus.util.order.ProviderComparator;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import java.util.*;

/**
 *
 */
@ApplicationScoped
public class AuthenticationInfoProviderHandler {

    @Inject
    private Instance<AuthenticationInfoProvider> authenticationInfoProviderInstances;

    private List<AuthenticationInfoProvider> authenticationInfoProviders;

    private List<AuthenticationStrategy> strategyValuesForProviders;

    @PostConstruct
    public void init() {
        retrieveProviders();

        Collections.sort(authenticationInfoProviders, new ProviderComparator());

        defineStrategy();
    }

    private void defineStrategy() {
        strategyValuesForProviders = new ArrayList<>();
        // FIXME Support of multiple AuthenticationStrategy.Required?
        for (AuthenticationInfoProvider authenticationInfoProvider : authenticationInfoProviders) {
            strategyValuesForProviders.add(authenticationInfoProvider.getAuthenticationStrategy());
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
            // TODO Is this properly logged ??
            throw new RealmConfigurationException("Missing implementation as CDI bean of SecurityDataProvider or AuthenticationInfoProvider");
        }
    }

    public AuthenticationInfo retrieveAuthenticationInfo(AuthenticationToken token) {
        prepareAuthenticationInfoProviders();  // To support the Java SE case.

        Iterator<AuthenticationInfoProvider> iterator = authenticationInfoProviders.iterator();
        AuthenticationInfo result = null;
        int idx = 0;
        boolean stopProcess = false;
        while (iterator.hasNext() && !stopProcess) {
            AuthenticationInfoProvider authenticationInfoProvider = iterator.next();
            AuthenticationInfo info = authenticationInfoProvider.getAuthenticationInfo(token);

            if (info != null && token instanceof SystemAuthenticationToken) {
                stopProcess = true;
                result = info;
            }

            if (info == null && strategyValuesForProviders.get(idx) == AuthenticationStrategy.REQUIRED) {
                // When required and returning null means not valid and thus fail.
                return null;
            }
            if (!stopProcess && info != null && noRequiredProvider(idx + 1)) {
                stopProcess = true;
                result = info;

            }

            class Guard {
            }
            if (!stopProcess && info != null) {
                ThreadContext.bindIntermediate(info.getPrincipals().getPrimaryPrincipal(), Guard.class);
            }

            idx++;
        }

        return result;
    }

    private boolean noRequiredProvider(int pos) {
        if (pos == strategyValuesForProviders.size()) {
            return true;
        }
        boolean result = true;
        for (int i = pos; i < strategyValuesForProviders.size(); i++) {
            if (strategyValuesForProviders.get(i) == AuthenticationStrategy.REQUIRED) {
                result = false;
            }
        }
        return result;
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

            if (authenticationInfoProviders.isEmpty()) {
                // TODO Is this properly logged ??
                throw new RealmConfigurationException("Missing configuration for SecurityDataProvider or AuthenticationInfoProvider");
            }

            Collections.sort(authenticationInfoProviders, new ProviderComparator());
            defineStrategy();
        }
    }

}
