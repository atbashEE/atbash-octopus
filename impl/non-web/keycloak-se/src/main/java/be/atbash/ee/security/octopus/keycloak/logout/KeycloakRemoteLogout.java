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
package be.atbash.ee.security.octopus.keycloak.logout;

import be.atbash.ee.security.octopus.authc.RemoteLogoutHandler;
import be.atbash.ee.security.octopus.keycloak.adapter.KeycloakDeploymentHelper;
import be.atbash.ee.security.octopus.keycloak.adapter.KeycloakUserToken;
import be.atbash.ee.security.octopus.keycloak.config.OctopusKeycloakConfiguration;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.ServerRequest;

import java.io.IOException;

/**
 * Logs the current user from the keycloak instance. Used in Java SE  (not Java EE!).
 */

public class KeycloakRemoteLogout implements RemoteLogoutHandler {

    @Override
    public void onLogout(PrincipalCollection principals) {
        KeycloakUserToken user = principals.oneByType(KeycloakUserToken.class);
        if (user != null) {
            KeycloakDeployment deployment = KeycloakDeploymentHelper.loadDeploymentDescriptor(OctopusKeycloakConfiguration.getInstance().getLocationKeycloakFile());

            try {
                ServerRequest.invokeLogout(deployment, user.getAccessTokenResponse().getRefreshToken());
            } catch (IOException | ServerRequest.HttpFailure e) {
                throw new AtbashUnexpectedException(e);
            }
        }
        // else Logging !! TODO
    }
}
