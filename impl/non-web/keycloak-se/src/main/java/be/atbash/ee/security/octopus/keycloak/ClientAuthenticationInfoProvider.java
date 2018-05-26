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
package be.atbash.ee.security.octopus.keycloak;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.keycloak.adapter.*;
import be.atbash.ee.security.octopus.keycloak.config.OctopusKeycloakConfiguration;
import be.atbash.ee.security.octopus.realm.AuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import org.keycloak.adapters.KeycloakDeployment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.enterprise.context.ApplicationScoped;

/**
 *
 */
@ApplicationScoped
public class ClientAuthenticationInfoProvider implements AuthenticationInfoProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClientAuthenticationInfoProvider.class);

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        AuthenticationInfoBuilder builder = new AuthenticationInfoBuilder();
        if (token instanceof UsernamePasswordToken) {
            // for the Java SE use case
            KeycloakDeployment deployment = KeycloakDeploymentHelper.loadDeploymentDescriptor(OctopusKeycloakConfiguration.getInstance().getLocationKeycloakFile());
            KeycloakAuthenticator authenticator = new KeycloakAuthenticator(deployment);
            try {
                KeycloakUserToken keycloakUserToken = authenticator.authenticate((UsernamePasswordToken) token);

                builder.principalId(keycloakUserToken.getId());

                builder.name(keycloakUserToken.getName());
                builder.token(keycloakUserToken);

            } catch (KeycloakRemoteConnectionException | OIDCAuthenticationException e) {
                LOGGER.error(e.getMessage());
                return null;
            }

            return builder.build();
        }
        if (token instanceof KeycloakUserToken) {
            // For the Web use case
            KeycloakUserToken keycloakUserToken = (KeycloakUserToken) token;

            builder.principalId(keycloakUserToken.getId());

            builder.name(keycloakUserToken.getName());
            builder.token(keycloakUserToken);

            return builder.build();

        }
        return null;
    }
}
