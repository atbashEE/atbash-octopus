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
package be.atbash.ee.security.octopus.sso.client.requestor;

import be.atbash.ee.security.octopus.authz.permission.NamedDomainPermission;
import be.atbash.ee.security.octopus.authz.permission.PermissionJSONProvider;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.sso.client.config.OctopusSSOServerClientConfiguration;
import net.jadler.Jadler;
import org.glassfish.jersey.client.ClientConfig;
import org.glassfish.jersey.jackson.JacksonFeature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class PermissionRequestorTest {

    @Mock
    private OctopusCoreConfiguration octopusCoreConfigurationMock;

    @Mock
    private OctopusSSOServerClientConfiguration octopusSSOServerClientConfigurationMock;

    private PermissionRequestor permissionRequestor;

    @BeforeEach
    public void setup() {
        ClientConfig clientConfiguration = new ClientConfig();
        clientConfiguration.register(JacksonFeature.class);

        permissionRequestor = new PermissionRequestor(octopusCoreConfigurationMock, octopusSSOServerClientConfigurationMock, null, clientConfiguration, new PermissionJSONProvider());
        Jadler.initJadler();
    }

    @AfterEach
    public void tearDown() {
        Jadler.closeJadler();
    }

    @Test
    public void retrieveUserPermissions() {
        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost:" + Jadler.port() + "/oidc");
        when(octopusSSOServerClientConfigurationMock.getSSOEndpointRoot()).thenReturn("data");
        when(octopusSSOServerClientConfigurationMock.getSSOApplication()).thenReturn("junitApp");


        Jadler.onRequest()
                .havingPathEqualTo("/oidc/data/octopus/sso/user/permissions/junitApp")
                .havingHeader("Authorization")
                .respond()
                .withContentType("application/json")
                .withBody("{\"permission1\":\"permission:1:*\",\"permission2\":\"permission:2:*\"}");


        String accessToken = "TheAccessToken";
        List<NamedDomainPermission> permissions = permissionRequestor.retrieveUserPermissions(accessToken);
        assertThat(permissions).isNotEmpty();
        assertThat(permissions.get(0).getName()).isEqualTo("permission1");
        assertThat(permissions.get(0).getWildcardNotation()).isEqualTo("permission:1:*");

    }

    @Test
    public void retrieveAllPermissions() {
        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost:" + Jadler.port() + "/oidc");
        when(octopusSSOServerClientConfigurationMock.getSSOEndpointRoot()).thenReturn("data");
        when(octopusSSOServerClientConfigurationMock.getSSOApplication()).thenReturn("junitApp");


        Jadler.onRequest()
                .havingPathEqualTo("/oidc/data/octopus/sso/permissions/junitApp")
                .respond()
                .withContentType("application/json")
                .withBody("{\"permission1\":\"permission:1:*\",\"permission2\":\"permission:2:*\"}");

        List<NamedDomainPermission> permissions = permissionRequestor.retrieveAllPermissions();
        assertThat(permissions).isNotEmpty();
        assertThat(permissions.get(0).getName()).isEqualTo("permission1");
        assertThat(permissions.get(0).getWildcardNotation()).isEqualTo("permission:1:*");
    }

    @Test
    public void retrieveAllPermissions_Empty() {
        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost:" + Jadler.port() + "/oidc");
        when(octopusSSOServerClientConfigurationMock.getSSOEndpointRoot()).thenReturn("data");
        when(octopusSSOServerClientConfigurationMock.getSSOApplication()).thenReturn("junitApp");

        Jadler.onRequest()
                .havingPathEqualTo("/oidc/data/octopus/sso/permissions/junitApp")
                .respond()
                .withContentType("application/json")
                .withBody("{}");

        List<NamedDomainPermission> permissions = permissionRequestor.retrieveAllPermissions();
        assertThat(permissions).isEmpty();
    }

    @Test
    public void retrieveAllPermissions_Failure() {
        when(octopusSSOServerClientConfigurationMock.getOctopusSSOServer()).thenReturn("http://localhost:" + Jadler.port() + "/oidc");
        when(octopusSSOServerClientConfigurationMock.getSSOEndpointRoot()).thenReturn("data");
        when(octopusSSOServerClientConfigurationMock.getSSOApplication()).thenReturn("junitApp");

        Jadler.onRequest()
                .havingPathEqualTo("/oidc/data/octopus/sso/permissions/junitApp")
                .respond()
                .withStatus(400)
                .withContentType("application/json")
                .withBody("Failure message");

        List<NamedDomainPermission> permissions = permissionRequestor.retrieveAllPermissions();
        assertThat(permissions).isEmpty();

        // TODO Catch logging

    }

}