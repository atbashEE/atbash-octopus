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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.crypto.hash.HashEncoding;
import be.atbash.ee.security.octopus.crypto.hash.HashFactory;
import be.atbash.util.TestReflectionUtils;
import com.google.common.collect.ImmutableList;
import org.junit.After;
import org.junit.Test;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.LoggingEvent;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


public class OctopusCoreConfigurationTest {

    private OctopusCoreConfiguration coreConfiguration = OctopusCoreConfiguration.getInstance();

    private TestLogger logger = TestLoggerFactory.getTestLogger(OctopusCoreConfiguration.class);

    @After
    public void tearDown() throws NoSuchFieldException {
        TestConfig.resetConfig();
        TestReflectionUtils.resetOf(coreConfiguration, "debugValues");
        // Config value is cached.
        logger.clearAll();
    }

    @Test
    public void showDebugFor() {
        TestConfig.addConfigValue("show.debug", "SSO_FLOW, SESSION_HIJACKING");
        List<Debug> debugFor = coreConfiguration.showDebugFor();

        assertThat(debugFor).hasSize(2);
        assertThat(debugFor).containsOnly(Debug.SSO_FLOW, Debug.SESSION_HIJACKING);

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).isEmpty();

    }

    @Test
    public void showDebugFor_emptyConfig() {
        List<Debug> debugFor = coreConfiguration.showDebugFor();

        assertThat(debugFor).isEmpty();

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).isEmpty();

    }

    @Test
    public void showDebugFor_properCleanup() {
        TestConfig.addConfigValue("show.debug", "SSO_FLOW, ,SESSION_HIJACKING   ,");
        List<Debug> debugFor = coreConfiguration.showDebugFor();

        assertThat(debugFor).hasSize(2);
        assertThat(debugFor).containsOnly(Debug.SSO_FLOW, Debug.SESSION_HIJACKING);

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).isEmpty();

    }

    @Test
    public void showDebugFor_unknown() {
        TestConfig.addConfigValue("show.debug", "TEST");
        List<Debug> debugFor = coreConfiguration.showDebugFor();

        assertThat(debugFor).isEmpty();

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).hasSize(1);
        LoggingEvent event = events.get(0);
        assertThat(event.getLevel()).isEqualTo(Level.ERROR);
        assertThat(event.getMessage()).isEqualTo("Value defined in the show.debug property unknown: {}");
        // Message is not interpolated
    }

    @Test
    public void getHashEncoding_default() {
        HashEncoding encoding = coreConfiguration.getHashEncoding();
        assertThat(encoding).isEqualTo(HashEncoding.HEX);
    }

    @Test
    public void getHashEncoding() {
        TestConfig.addConfigValue("hashEncoding", "BASE64");
        HashEncoding encoding = coreConfiguration.getHashEncoding();
        assertThat(encoding).isEqualTo(HashEncoding.BASE64);
    }

    @Test(expected = ConfigurationException.class)
    public void getHashEncoding_WrongValue() {
        TestConfig.addConfigValue("hashEncoding", "TEST");
        coreConfiguration.getHashEncoding();

    }

    @Test
    public void getHashIterations() {
        // FIXME
        Integer iterations = coreConfiguration.getHashIterations();

    }
}