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
package be.atbash.ee.security.octopus.cas.logout;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import net.jadler.Jadler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static be.atbash.ee.security.octopus.OctopusConstants.UPSTREAM_TOKEN;

public class CasRemoteLogoutTest {

    private CasRemoteLogout logout;

    @BeforeEach
    public void setUp() {
        logout = new CasRemoteLogout();
        Jadler.initJadler();
    }


    @AfterEach
    public void teardown() {
        TestConfig.resetConfig();
        Jadler.closeJadler();
    }

    @Test
    public void onLogout() {

        TestConfig.addConfigValue("CAS.SSO.server", "http://localhost:" + Jadler.port() + "/cas");

        Jadler.onRequest()
                .havingPathEqualTo("/cas/v1/tickets/TGT")
                .respond()
                .withStatus(200);

        UserPrincipal userPrincipal = new UserPrincipal(123L, "octopus", "Junit Octopus Test");
        userPrincipal.addUserInfo(UPSTREAM_TOKEN, "TGT");
        PrincipalCollection principals = new PrincipalCollection(userPrincipal);

        logout.onLogout(principals);
    }

}