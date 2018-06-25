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
package be.atbash.ee.security.octopus.keycloak.view;

import be.atbash.ee.security.octopus.keycloak.TestBoundary;
import be.atbash.ee.security.octopus.keycloak.adapter.KeycloakUserToken;
import be.atbash.ee.security.octopus.subject.PrincipalManager;

import javax.enterprise.inject.Model;
import javax.inject.Inject;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;

import static be.atbash.ee.security.octopus.WebConstants.AUTHORIZATION_HEADER;
import static be.atbash.ee.security.octopus.WebConstants.BEARER;

/**
 *
 */
@Model
public class TestBean {

    @Inject
    private TestBoundary testBoundary;

    @Inject
    private PrincipalManager principalManager;

    public void testAuthorization() {
        testBoundary.doSomething();
    }

    public void testRemoteCall() {
        KeycloakUserToken keycloakUserToken = principalManager.convert(KeycloakUserToken.class);
        String token = keycloakUserToken.getAccessToken();

        Client client = ClientBuilder.newClient();
        WebTarget webTarget
                = client.target("http://localhost:8080/keycloak_rest/data/hello/cascaded");

        Response response = webTarget.request()
                .header(AUTHORIZATION_HEADER, BEARER + " " + token)
                .get();
        System.out.println(response.getStatus());
        System.out.println(response.readEntity(String.class));
    }

}
