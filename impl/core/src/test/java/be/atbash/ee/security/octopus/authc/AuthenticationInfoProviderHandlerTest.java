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

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.authc.testclasses.SystemToken;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class AuthenticationInfoProviderHandlerTest {

    private AuthenticationInfoProviderHandler handler;

    @Before
    public void setup() {
        handler = new AuthenticationInfoProviderHandler();
    }

    @After
    public void cleanup() {
        TestConfig.resetConfig();
    }

    @Test
    public void retrieveAuthenticationInfo() {

        TestConfig.addConfigValue("authenticationInfoProvider.class", "be.atbash.ee.security.octopus.authc.testclasses.RequiredAuthenticationProvider");

        AuthenticationToken token = new UsernamePasswordToken("JUnit", "Password".toCharArray());
        AuthenticationInfo info = handler.retrieveAuthenticationInfo(token);

        assertThat(info).isNotNull();
        // Check to see if the correct provider has given us the Info
        assertThat(info.getPrincipals().getPrimaryPrincipal().getId()).isEqualTo("RequiredAuthenticationProvider");

    }

    @Test
    public void retrieveAuthenticationInfo_unknown() {

        TestConfig.addConfigValue("authenticationInfoProvider.class", "be.atbash.ee.security.octopus.authc.testclasses.RequiredAuthenticationProvider");

        AuthenticationToken token = new UsernamePasswordToken("unknown", "xx".toCharArray());
        AuthenticationInfo info = handler.retrieveAuthenticationInfo(token);

        assertThat(info).isNull();

    }

    @Test
    public void retrieveAuthenticationInfo_systemAuthenticationToken() {

        TestConfig.addConfigValue("authenticationInfoProvider.class", "be.atbash.ee.security.octopus.authc.testclasses.RequiredAuthenticationProvider,be.atbash.ee.security.octopus.authc.testclasses.SystemAuthenticationProvider");

        AuthenticationToken token = new SystemToken();
        AuthenticationInfo info = handler.retrieveAuthenticationInfo(token);

        assertThat(info).isNotNull();
        // Check to see if the correct provider has given us the Info
        assertThat(info.getPrincipals().getPrimaryPrincipal().getId()).isEqualTo("SystemAuthenticationProvider");
        // Although RequiredAuthenticationProvider is defined as required, the SystemAuthenticationProvider is enough (because it is a systemAuthenticationToken)

    }

    @Test
    public void retrieveAuthenticationInfo_sufficientFirstMatch() {

        TestConfig.addConfigValue("authenticationInfoProvider.class", "be.atbash.ee.security.octopus.authc.testclasses.Sufficient2AuthenticationProvider,be.atbash.ee.security.octopus.authc.testclasses.Sufficient1AuthenticationProvider");

        AuthenticationToken token = new UsernamePasswordToken("test", "pw".toCharArray());
        AuthenticationInfo info = handler.retrieveAuthenticationInfo(token);

        assertThat(info).isNotNull();
        // Check to see if the correct provider has given us the Info
        assertThat(info.getPrincipals().getPrimaryPrincipal().getId()).isEqualTo("Sufficient1AuthenticationProvider");
        // Sufficient1AuthenticationProvider has a match and thus second provider isn't called.

    }

    @Test
    public void retrieveAuthenticationInfo_sufficientSecondMatch() {

        TestConfig.addConfigValue("authenticationInfoProvider.class", "be.atbash.ee.security.octopus.authc.testclasses.Sufficient2AuthenticationProvider,be.atbash.ee.security.octopus.authc.testclasses.Sufficient1AuthenticationProvider");

        AuthenticationToken token = new UsernamePasswordToken("Test123", "pw".toCharArray());
        AuthenticationInfo info = handler.retrieveAuthenticationInfo(token);

        assertThat(info).isNotNull();
        // Check to see if the correct provider has given us the Info
        assertThat(info.getPrincipals().getPrimaryPrincipal().getId()).isEqualTo("Sufficient2AuthenticationProvider");
        // Sufficient1AuthenticationProvider has no match and thus second provider is called.

    }

    @Test
    public void retrieveAuthenticationInfo_sufficientAndRequired() {

        TestConfig.addConfigValue("authenticationInfoProvider.class", "be.atbash.ee.security.octopus.authc.testclasses.Sufficient2AuthenticationProvider,be.atbash.ee.security.octopus.authc.testclasses.RequiredAuthenticationProvider");

        AuthenticationToken token = new UsernamePasswordToken("test", "pw".toCharArray());
        AuthenticationInfo info = handler.retrieveAuthenticationInfo(token);

        assertThat(info).isNotNull();
        // Check to see if the correct provider has given us the Info
        assertThat(info.getPrincipals().getPrimaryPrincipal().getId()).isEqualTo("RequiredAuthenticationProvider");
        // although Sufficient2AuthenticationProvider has a match, a required is defined and thus that ons takes precedence.

    }

    @Test
    public void retrieveAuthenticationInfo_wrongOrderRequiredSufficient() {

        TestConfig.addConfigValue("authenticationInfoProvider.class", "be.atbash.ee.security.octopus.authc.testclasses.Sufficient1AuthenticationProvider,be.atbash.ee.security.octopus.authc.testclasses.RequiredAuthenticationProvider");

        AuthenticationToken token = new UsernamePasswordToken("unknown", "pw".toCharArray());
        AuthenticationInfo info = handler.retrieveAuthenticationInfo(token);

        assertThat(info).isNull();

        // although Sufficient1AuthenticationProvider has a match, a required is defined first and thus that ons takes precedence.

    }

    @Test
    public void retrieveAuthenticationInfo_TwoRequired() {

        TestConfig.addConfigValue("authenticationInfoProvider.class", "be.atbash.ee.security.octopus.authc.testclasses.RequiredAuthenticationProvider,be.atbash.ee.security.octopus.authc.testclasses.ExtraRequiredAuthenticationProvider");

        AuthenticationToken token = new UsernamePasswordToken("JUnit", "pw".toCharArray());
        AuthenticationInfo info = handler.retrieveAuthenticationInfo(token);

        assertThat(info).isNotNull();

        assertThat(info.getPrincipals().getPrimaryPrincipal().getId()).isEqualTo("RequiredAuthenticationProvider");
        assertThat(info.getCredentials()).isEqualTo("fromExtra");


    }
}