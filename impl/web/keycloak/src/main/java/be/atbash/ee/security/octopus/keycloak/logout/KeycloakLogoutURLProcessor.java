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
package be.atbash.ee.security.octopus.keycloak.logout;

import be.atbash.ee.security.octopus.keycloak.adapter.KeycloakDeploymentHelper;
import be.atbash.ee.security.octopus.keycloak.config.OctopusKeycloakConfiguration;
import be.atbash.ee.security.octopus.logout.LogoutParameters;
import be.atbash.ee.security.octopus.logout.LogoutURLProcessor;
import org.keycloak.OAuth2Constants;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.common.util.KeycloakUriBuilder;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 *
 */
@ApplicationScoped
public class KeycloakLogoutURLProcessor implements LogoutURLProcessor {

    @Inject
    private OctopusKeycloakConfiguration keycloakConfiguration;

    private KeycloakDeployment deployment;

    @PostConstruct
    public void init() {
        deployment = KeycloakDeploymentHelper.loadDeploymentDescriptor(keycloakConfiguration.getLocationKeycloakFile());
    }

    @Override
    public String postProcessLogoutUrl(String logoutURL, LogoutParameters logoutParameters) {
        // FIXME, we need to know which authenticationSource the user used. Otherwise we can send the logout to the wrong authenticator.

        if (logoutParameters.isSingleLogout()) {
            KeycloakUriBuilder builder = deployment.getLogoutUrl().clone()
                    .queryParam(OAuth2Constants.REDIRECT_URI, logoutURL);

            return builder.build().toString();
        } else {
            return logoutURL;
        }

    }

}
