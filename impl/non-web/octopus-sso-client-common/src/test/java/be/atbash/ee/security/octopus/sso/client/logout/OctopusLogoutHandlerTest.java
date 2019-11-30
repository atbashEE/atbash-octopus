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
package be.atbash.ee.security.octopus.sso.client.logout;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import net.jadler.Jadler;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.util.Base64;
import java.util.Random;

import static org.assertj.core.api.Assertions.assertThat;

public class OctopusLogoutHandlerTest {

    private Random random = new Random();

    @Before
    public void setup() {
        Jadler.initJadler();
    }

    @After
    public void teardown() {
        Jadler.closeJadler();
        TestConfig.resetConfig();
        TestLoggerFactory.clear();
    }

    @Test
    public void onLogout() {
        defineClientSecret();
        TestConfig.addConfigValue("SSO.clientId", "clientId");
        TestConfig.addConfigValue("SSO.octopus.server", "http://localhost:" + Jadler.port() + "/server");

        OctopusLogoutHandler handler = new OctopusLogoutHandler();

        UserPrincipal userPricipal = new UserPrincipal(1L, "junit", "JUnit");
        PrincipalCollection principals = new PrincipalCollection(userPricipal);

        OctopusSSOToken octopusSSOToken = new OctopusSSOToken();
        octopusSSOToken.setBearerAccessToken(new BearerAccessToken("theAccessCode"));
        principals.add(octopusSSOToken);

        Jadler.onRequest().havingPathEqualTo("/server/octopus/sso/logout")
                .havingQueryString(new QueryStringMatcher())
                .respond()
                .withStatus(200);

        TestLogger logger = TestLoggerFactory.getTestLogger(OctopusLogoutHandler.class);

        handler.onLogout(principals);

        assertThat(logger.getLoggingEvents()).isEmpty();
    }


    @Test
    public void onLogout_failedRequest() {
        defineClientSecret();
        TestConfig.addConfigValue("SSO.clientId", "clientId");
        TestConfig.addConfigValue("SSO.octopus.server", "http://localhost:" + Jadler.port() + "/server");

        OctopusLogoutHandler handler = new OctopusLogoutHandler();

        UserPrincipal userPricipal = new UserPrincipal(1L, "junit", "JUnit");
        PrincipalCollection principals = new PrincipalCollection(userPricipal);

        OctopusSSOToken octopusSSOToken = new OctopusSSOToken();
        octopusSSOToken.setBearerAccessToken(new BearerAccessToken("theAccessCode"));
        principals.add(octopusSSOToken);

        Jadler.onRequest().havingPathEqualTo("/server/octopus/sso/logout")
                .respond()
                .withStatus(400);

        TestLogger logger = TestLoggerFactory.getTestLogger(OctopusLogoutHandler.class);

        handler.onLogout(principals);

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Received invalid status on the logout URL of Octopus SSO Server : 400");
    }

    private void defineClientSecret() {
        byte[] value = new byte[32];
        random.nextBytes(value);
        TestConfig.addConfigValue("SSO.clientSecret", Base64.getUrlEncoder().withoutPadding().encodeToString(value));
    }

    private static class QueryStringMatcher extends BaseMatcher<String> {

        @Override
        public boolean matches(Object item) {
            String queryString = item.toString();
            return !queryString.contains("post_logout_redirect_uri");
        }

        @Override
        public void describeTo(Description description) {

        }
    }
}