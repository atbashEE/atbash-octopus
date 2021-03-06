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
package be.atbash.ee.security.octopus.keycloak.rest;

import be.atbash.ee.security.octopus.keycloak.adapter.KeycloakUserToken;
import be.atbash.ee.security.octopus.subject.PrincipalManager;

import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientRequestFilter;
import java.io.IOException;

/**
 *
 */

public class KeycloakRestClientProvider implements ClientRequestFilter {
    // Class name used in a string within OctopusRestClientBuilderListener. Don't refactor unless you change that class!!

    @Override
    public void filter(ClientRequestContext clientRequestContext) throws IOException {
        KeycloakUserToken keycloakUserToken = PrincipalManager.getInstance().convert(KeycloakUserToken.class);

        clientRequestContext.getHeaders().add("authorization", "Bearer " + keycloakUserToken.getAccessToken());
    }

}
