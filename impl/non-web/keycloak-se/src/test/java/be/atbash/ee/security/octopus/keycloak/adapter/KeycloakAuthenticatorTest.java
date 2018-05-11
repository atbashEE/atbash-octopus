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
package be.atbash.ee.security.octopus.keycloak.adapter;

import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersNone;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import net.jadler.Jadler;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.adapters.config.AdapterConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class KeycloakAuthenticatorTest {

    private KeycloakAuthenticator authenticator;

    @Before
    public void setUp() {
        Jadler.initJadler();
    }

    @After
    public void tearDown() {
        Jadler.closeJadler();
    }

    @Test
    public void authenticate() {

        AccessTokenResponse response = new AccessTokenResponse();
        response.setToken("accessToken");

        JWTEncoder encoder = new JWTEncoder();
        Jadler.onRequest().havingMethodEqualTo("POST")
                .respond().withBody(encoder.encode(response, new JWTParametersNone()));
        AdapterConfig adapterConfig = new AdapterConfig();
        adapterConfig.setRealm("test");
        adapterConfig.setAuthServerUrl("http://localhost:" + Jadler.port());
        adapterConfig.setResource("demo");

        authenticator = new KeycloakAuthenticator(KeycloakDeploymentBuilder.build(adapterConfig));

        UsernamePasswordToken token = new UsernamePasswordToken("Atbash", "JUnit");
        try {
            authenticator.authenticate(token);
        } catch (OIDCAuthenticationException e) {
            // expected, The AccessToken is not a real one and thus processing it as a JWT fails with this exception.
        }

        Jadler.verifyThatRequest().havingParameterEqualTo("username", "Atbash")
                .havingParameterEqualTo("password", "JUnit").receivedOnce();
    }

    @Test
    public void authenticate_unknown() {

        Jadler.onRequest().havingMethodEqualTo("POST")
                .respond().withStatus(401).withBody("Invalid credentials");
        AdapterConfig adapterConfig = new AdapterConfig();
        adapterConfig.setRealm("test");
        adapterConfig.setAuthServerUrl("http://localhost:" + Jadler.port());
        adapterConfig.setResource("demo");

        authenticator = new KeycloakAuthenticator(KeycloakDeploymentBuilder.build(adapterConfig));

        UsernamePasswordToken token = new UsernamePasswordToken("Atbash", "JUnit");
        try {
            authenticator.authenticate(token);
        } catch (KeycloakRemoteConnectionException e) {
            assertThat(e.getMessage()).isEqualTo("Bad status: 401, message 'Invalid credentials'");
        }

        Jadler.verifyThatRequest().havingParameterEqualTo("username", "Atbash")
                .havingParameterEqualTo("password", "JUnit").receivedOnce();
    }

}