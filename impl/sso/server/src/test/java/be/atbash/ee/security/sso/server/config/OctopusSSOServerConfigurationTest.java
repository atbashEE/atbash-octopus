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
package be.atbash.ee.security.sso.server.config;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.ee.security.octopus.sso.core.config.JARMLevel;
import org.junit.After;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class OctopusSSOServerConfigurationTest {

    private OctopusSSOServerConfiguration configuration = new OctopusSSOServerConfiguration();

    @After
    public void teardown() {
        TestConfig.resetConfig();
    }

    @Test
    public void getSSOCookieTimeToLive_hours() {
        TestConfig.addConfigValue("SSO.cookie.timetolive", "8h");

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(8 * 3600);
    }

    @Test
    public void getSSOCookieTimeToLive_default() {

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10 * 3600);
    }

    @Test
    public void getOIDCTokenLength_default() {
        int tokenLength = configuration.getOIDCTokenLength();
        assertThat(tokenLength).isEqualTo(32);
    }

    @Test(expected = ConfigurationException.class)
    public void getOIDCTokenLength_minimalValue() {
        TestConfig.addConfigValue("SSO.token.length", "31");
        configuration.getOIDCTokenLength();

    }

    @Test(expected = ConfigurationException.class)
    public void getOIDCTokenLength_nonNumeric() {
        TestConfig.addConfigValue("SSO.token.length", "abc");
        configuration.getOIDCTokenLength();

    }

    @Test(expected = ConfigurationException.class)
    public void getOIDCTokenLength_empty() {
        TestConfig.addConfigValue("SSO.token.length", "");
        configuration.getOIDCTokenLength();

    }

    @Test
    public void getSSOAccessTokenTimeToLive_hours() {
        TestConfig.addConfigValue("SSO.access.token.timetolive", "8h");

        int ssoCookieTimeToLive = configuration.getSSOAccessTokenTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(8 * 60 * 60);
    }

    @Test
    public void getSSOAccessTokenTimeToLive_default() {

        int ssoCookieTimeToLive = configuration.getSSOAccessTokenTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(3600);
    }

    @Test
    public void getUserEndpointEncoding_default() {
        UserEndpointEncoding encoding = configuration.getUserEndpointEncoding();
        assertThat(encoding).isEqualTo(UserEndpointEncoding.NONE);
    }

    @Test
    public void getUserEndpointEncoding() {
        TestConfig.addConfigValue("SSO.user.endpoint.encoding", "JWS");
        UserEndpointEncoding encoding = configuration.getUserEndpointEncoding();
        assertThat(encoding).isEqualTo(UserEndpointEncoding.JWS);
    }

    @Test(expected = ConfigurationException.class)
    public void getUserEndpointEncoding_invalid() {
        TestConfig.addConfigValue("SSO.user.endpoint.encoding", "something");
        configuration.getUserEndpointEncoding();

    }

    @Test
    public void getJARMLevel_default() {
        JARMLevel level = configuration.getJARMLevel();
        assertThat(level).isEqualTo(JARMLevel.NONE);
    }

    @Test
    public void getJARMLevel() {
        TestConfig.addConfigValue("SSO.jarm.level", "JWS");
        JARMLevel level = configuration.getJARMLevel();
        assertThat(level).isEqualTo(JARMLevel.JWS);
    }

    @Test(expected = ConfigurationException.class)
    public void getJARMLevel_invalid() {
        TestConfig.addConfigValue("SSO.jarm.level", "something");
        configuration.getJARMLevel();
    }

    @Test
    public void getJarmSigningKeyId() {
        TestConfig.addConfigValue("SSO.jarm.level", "JWT");
        TestConfig.addConfigValue("SSO.jarm.sign.kid", "kidId");
        String keyId = configuration.getJarmSigningKeyId();
        assertThat(keyId).isEqualTo("kidId");
    }

    @Test(expected = ConfigurationException.class)
    public void getJarmSigningKeyId_missing() {
        TestConfig.addConfigValue("SSO.jarm.level", "JWT");
        configuration.getJarmSigningKeyId();

    }
}