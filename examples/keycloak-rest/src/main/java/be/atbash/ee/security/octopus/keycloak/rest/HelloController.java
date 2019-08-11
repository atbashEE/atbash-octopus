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
package be.atbash.ee.security.octopus.keycloak.rest;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.authz.annotation.RequiresPermissions;
import be.atbash.ee.security.octopus.authz.annotation.RequiresUser;
import be.atbash.ee.security.octopus.keycloak.adapter.KeycloakUserToken;
import be.atbash.ee.security.octopus.subject.PrincipalManager;
import be.atbash.ee.security.octopus.subject.UserPrincipal;

import javax.inject.Inject;
import javax.inject.Singleton;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Response;


/**
 *
 */
@Path("/hello")
@Singleton
public class HelloController {

    @Inject
    private UserPrincipal principal;

    @Inject
    private PrincipalManager principalManager;

    @GET
    @RequiresUser
    public String sayHello() {
        return "Hello " + principal.getName();
    }

    @GET
    @Path("cascaded")
    @RequiresUser
    public String sayHelloCascaded() {
        KeycloakUserToken keycloakUserToken = principalManager.convert(KeycloakUserToken.class);
        String token = keycloakUserToken.getAccessToken();

        Client client = ClientBuilder.newClient();
        WebTarget webTarget
                = client.target("http://localhost:8080/keycloak_rest/data/hello");

        Response response = webTarget.request()
                .header(OctopusConstants.AUTHORIZATION_HEADER, OctopusConstants.BEARER + " " + token)
                .get();

        return "cascaded :" + response.readEntity(String.class);

    }

    @Path("/protectedPermission1")
    @RequiresPermissions("demo:read:*")
    @GET
    public String testPermission1() {
        return "Has permission demo:read:*";
    }

    @Path("/protectedPermission2")
    @RequiresPermissions("demo:write:*")
    @GET
    public String testPermission2() {
        return "Has permission demo:write:*";
    }
}
