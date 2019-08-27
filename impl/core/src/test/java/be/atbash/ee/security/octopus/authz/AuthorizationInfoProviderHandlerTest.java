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
package be.atbash.ee.security.octopus.authz;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import org.junit.After;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


public class AuthorizationInfoProviderHandlerTest {

    @After
    public void cleanup() {
        TestConfig.resetConfig();
        System.setProperty("atbash.utils.cdi.check", "");
    }

    @Test
    public void retrieveAuthorizationInfo() {
        System.setProperty("atbash.utils.cdi.check", "false");
        TestConfig.addConfigValue("authorizationInfoProvider.class", "be.atbash.ee.security.octopus.authz.testclasses.FirstProvider");

        AuthorizationInfoProviderHandler handler = new AuthorizationInfoProviderHandler();
        UserPrincipal primary = new UserPrincipal(1L, "junit", "JUnit");

        AuthorizationInfo info = handler.retrieveAuthorizationInfo(new PrincipalCollection(primary));
        assertThat(info.getStringPermissions()).hasSize(1);
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();

    }

    @Test
    public void retrieveAuthorizationInfo_multiple() {
        System.setProperty("atbash.utils.cdi.check", "false");
        TestConfig.addConfigValue("authorizationInfoProvider.class", "be.atbash.ee.security.octopus.authz.testclasses.FirstProvider,be.atbash.ee.security.octopus.authz.testclasses.SecondProvider");

        AuthorizationInfoProviderHandler handler = new AuthorizationInfoProviderHandler();
        UserPrincipal primary = new UserPrincipal(1L, "junit", "JUnit");

        AuthorizationInfo info = handler.retrieveAuthorizationInfo(new PrincipalCollection(primary));
        assertThat(info.getStringPermissions()).hasSize(2);
        assertThat(info.getObjectPermissions()).hasSize(2);
        assertThat(info.getRoles()).isEmpty();

    }

    @Test
    public void retrieveAuthorizationInfo_none() {
        System.setProperty("atbash.utils.cdi.check", "false");
        TestConfig.addConfigValue("authorizationInfoProvider.class", "");

        AuthorizationInfoProviderHandler handler = new AuthorizationInfoProviderHandler();
        UserPrincipal primary = new UserPrincipal(1L, "junit", "JUnit");

        AuthorizationInfo info = handler.retrieveAuthorizationInfo(new PrincipalCollection(primary));
        assertThat(info.getStringPermissions()).isEmpty();
        assertThat(info.getObjectPermissions()).isEmpty();
        assertThat(info.getRoles()).isEmpty();

    }


}