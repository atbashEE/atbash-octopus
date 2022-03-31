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
package be.atbash.ee.security.octopus.authz;

import be.atbash.ee.security.octopus.config.InfoProviderConfiguration;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import org.slf4j.Logger;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 *
 */
@ApplicationScoped
public class AuthorizationInfoProviderHandler {

    @Inject
    private Logger logger;

    @Inject
    private Instance<AuthorizationInfoProvider> authorizationInfoProvidersInstances;

    private List<AuthorizationInfoProvider> authorizationInfoProviders;

    @PostConstruct
    public void init() {
        retrieveProviders();
    }

    private void retrieveProviders() {
        authorizationInfoProviders = new ArrayList<>();
        if (!authorizationInfoProvidersInstances.isUnsatisfied()) {
            for (AuthorizationInfoProvider authorizationInfoProvider : authorizationInfoProvidersInstances.select()) {
                authorizationInfoProviders.add(authorizationInfoProvider);
            }
        }

        if (authorizationInfoProviders.isEmpty()) {
            logger.warn("OCT-??? Missing implementation(s) as CDI bean of SecurityDataProvider or AuthorizationInfoProvider");
        }
    }

    public AuthorizationInfo retrieveAuthorizationInfo(PrincipalCollection principals) {
        prepareAuthorizationInfoProviders();

        if (authorizationInfoProviders.isEmpty()) {
            return new SimpleAuthorizationInfo();
        } else {
            MergeableAuthorizationInfo result = new MergeableAuthorizationInfo();
            for (AuthorizationInfoProvider provider : authorizationInfoProviders) {
                AuthorizationInfo authorizationInfo = provider.getAuthorizationInfo(principals);
                result.merge(authorizationInfo);
            }
            return result;
        }
    }

    private void prepareAuthorizationInfoProviders() {
        if (authorizationInfoProviders == null) {
            // From configuration, Developer defined.
            InfoProviderConfiguration config = new InfoProviderConfiguration();
            authorizationInfoProviders = config.getAuthorizationInfoProviders();

            // From the Octopus modules.
            ServiceLoader<AuthorizationInfoProvider> providers = ServiceLoader.load(AuthorizationInfoProvider.class);
            for (AuthorizationInfoProvider provider : providers) {
                authorizationInfoProviders.add(provider);
            }

        }
    }

}
