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
import com.google.common.collect.ImmutableList;
import org.junit.After;
import org.junit.Test;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.LoggingEvent;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;

public class OctopusSSOServerConfigurationTest {

    private OctopusSSOServerConfiguration configuration = new OctopusSSOServerConfiguration();

    private TestLogger logger = TestLoggerFactory.getTestLogger(OctopusSSOServerConfiguration.class);

    @After
    public void teardown() {
        TestConfig.resetConfig();
        TestLoggerFactory.clear();
    }

    @Test
    public void getSSOCookieTimeToLive_hours() {
        TestConfig.addConfigValue("SSO.cookie.timetolive", "8h");

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(8 * 3600);
    }

    @Test
    public void getSSOCookieTimeToLive_days() {
        TestConfig.addConfigValue("SSO.cookie.timetolive", "12d");

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(12 * 24 * 3600);
    }

    @Test
    public void getSSOCookieTimeToLive_months() {
        TestConfig.addConfigValue("SSO.cookie.timetolive", "1m");

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(24 * 30 * 3600);
    }

    @Test
    public void getSSOCookieTimeToLive_default() {

        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10 * 3600);
    }

    @Test
    public void getSSOCookieTimeToLive_wrongValue() {
        TestConfig.addConfigValue("SSO.cookie.timetolive", "JUnit");
        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10 * 3600); // Default Value

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).hasSize(1);
        assertThat(events.get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(events.get(0).getMessage()).isEqualTo("Invalid configuration value for SSO.cookie.timetolive = JUnit. Using default of 10h");

    }

    @Test
    public void getSSOCookieTimeToLive_Zero() {
        TestConfig.addConfigValue("SSO.cookie.timetolive", "0h");
        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10 * 3600); // Default Value

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).hasSize(1);
        assertThat(events.get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(events.get(0).getMessage()).isEqualTo("Invalid configuration value for SSO.cookie.timetolive = 0h. Using default of 10h");

    }

    @Test
    public void getSSOCookieTimeToLive_negative() {
        TestConfig.addConfigValue("SSO.cookie.timetolive", "-1h");
        int ssoCookieTimeToLive = configuration.getSSOCookieTimeToLive();
        assertThat(ssoCookieTimeToLive).isEqualTo(10 * 3600); // Default Value

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).hasSize(1);
        assertThat(events.get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(events.get(0).getMessage()).isEqualTo("Invalid configuration value for SSO.cookie.timetolive = -1h. Using default of 10h");
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
}