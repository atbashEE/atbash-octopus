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
package be.atbash.ee.security.octopus.config;

import be.atbash.config.exception.ConfigurationException;
import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.authz.permission.NamedPermission;
import be.atbash.ee.security.octopus.authz.permission.role.NamedRole;
import be.atbash.ee.security.octopus.config.testclasses.DemoNamedPermission;
import be.atbash.ee.security.octopus.config.testclasses.DemoNamedRole;
import be.atbash.ee.security.octopus.config.testclasses.NamedCheck;
import be.atbash.ee.security.octopus.crypto.hash.HashEncoding;
import be.atbash.util.TestReflectionUtils;
import com.google.common.collect.ImmutableList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.LoggingEvent;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.lang.annotation.Annotation;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class OctopusCoreConfigurationTest {

    private OctopusCoreConfiguration coreConfiguration = OctopusCoreConfiguration.getInstance();

    private TestLogger logger = TestLoggerFactory.getTestLogger(OctopusCoreConfiguration.class);

    @AfterEach
    public void tearDown() throws NoSuchFieldException {
        TestConfig.resetConfig();
        TestReflectionUtils.resetOf(coreConfiguration, "debugValues");
        TestReflectionUtils.resetOf(coreConfiguration, "namedPermissionCheckClass");
        TestReflectionUtils.resetOf(coreConfiguration, "namedPermissionClass");
        TestReflectionUtils.resetOf(coreConfiguration, "namedRoleCheckClass");
        TestReflectionUtils.resetOf(coreConfiguration, "namedRoleClass");
        TestReflectionUtils.resetOf(coreConfiguration, "customCheckClass");

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

    @Test
    public void getHashEncoding_wrongValue() {
        TestConfig.addConfigValue("hashEncoding", "TEST");
        Assertions.assertThrows(ConfigurationException.class, () -> coreConfiguration.getHashEncoding());

    }

    @Test
    public void getSaltLength() {
        TestConfig.addConfigValue("saltLength", "16");
        Integer saltLength = coreConfiguration.getSaltLength();
        assertThat(saltLength).isEqualTo(16);
    }

    @Test
    public void getSaltLength_default() {
        Integer saltLength = coreConfiguration.getSaltLength();
        assertThat(saltLength).isEqualTo(0);
    }

    @Test
    public void getSaltLength_WrongValue() {
        TestConfig.addConfigValue("saltLength", "15");
        Assertions.assertThrows(ConfigurationException.class, () -> coreConfiguration.getSaltLength());
    }

    @Test
    public void getSaltLength_WrongValue_negative() {
        TestConfig.addConfigValue("saltLength", "-16");
        Assertions.assertThrows(ConfigurationException.class, () -> coreConfiguration.getSaltLength());
    }

    @Test
    public void getHashIterations() {
        TestConfig.addConfigValue("hashAlgorithmName", "SHA-256");
        TestConfig.addConfigValue("hashIterations", "2");
        Integer iterations = coreConfiguration.getHashIterations();
        assertThat(iterations).isEqualTo(2);
    }

    @Test
    public void getHashIterations_default_hash() {
        TestConfig.addConfigValue("hashAlgorithmName", "SHA-256");
        Integer iterations = coreConfiguration.getHashIterations();
        assertThat(iterations).isEqualTo(1);
    }

    @Test
    public void getHashIterations_default_keyFactory() {
        TestConfig.addConfigValue("hashAlgorithmName", "PBKDF2");
        Integer iterations = coreConfiguration.getHashIterations();
        assertThat(iterations).isEqualTo(1024);
    }

    @Test
    public void getHashIterations_noAlgorithm() {
        TestConfig.addConfigValue("hashIterations", "2");
        Integer iterations = coreConfiguration.getHashIterations();
        assertThat(iterations).isNull();
    }

    @Test
    public void getHashIterations_wrongValue() {
        TestConfig.addConfigValue("hashAlgorithmName", "SHA-256");
        TestConfig.addConfigValue("hashIterations", "0");
        Assertions.assertThrows(ConfigurationException.class, () -> coreConfiguration.getHashIterations());

    }

    @Test
    public void getHashIterations_NoNumber() {
        TestConfig.addConfigValue("hashAlgorithmName", "SHA-256");
        TestConfig.addConfigValue("hashIterations", "abc");
        Assertions.assertThrows(ConfigurationException.class, () -> coreConfiguration.getHashIterations());

    }

    @Test
    public void getNamedPermissionCheckClass() {
        TestConfig.addConfigValue("namedPermissionCheck.class", NamedCheck.class.getName());
        Class<? extends Annotation> checkClass = coreConfiguration.getNamedPermissionCheckClass();
        assertThat(checkClass).isNotNull();
    }

    @Test
    public void getNamedPermissionCheckClass_wrongClass() {
        TestConfig.addConfigValue("namedPermissionCheck.class", "some.unknown.class");
        Class<? extends Annotation> checkClass = coreConfiguration.getNamedPermissionCheckClass();
        assertThat(checkClass).isNull();

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).isNotEmpty();
    }

    @Test
    public void getCustomCheckClass() {
        TestConfig.addConfigValue("customCheck.class", NamedCheck.class.getName());
        Class<? extends Annotation> checkClass = coreConfiguration.getCustomCheckClass();
        assertThat(checkClass).isNotNull();
    }

    @Test
    public void getCustomCheckClass_wrongClass() {
        TestConfig.addConfigValue("customCheck.class", "some.unknown.class");
        Class<? extends Annotation> checkClass = coreConfiguration.getCustomCheckClass();
        assertThat(checkClass).isNull();

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).isNotEmpty();
    }

    @Test
    public void getNamedPermissionClass() {
        TestConfig.addConfigValue("namedPermission.class", DemoNamedPermission.class.getName());
        Class<? extends NamedPermission> permissionClass = coreConfiguration.getNamedPermissionClass();
        assertThat(permissionClass).isNotNull();
    }

    @Test
    public void getNamedPermissionClass_wrongClass() {
        TestConfig.addConfigValue("namedPermission.class", "some.unknown.class");
        Class<? extends NamedPermission> permissionClass = coreConfiguration.getNamedPermissionClass();
        assertThat(permissionClass).isNull();

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).isNotEmpty();
    }

    @Test
    public void getNamedRoleCheckClass() {
        TestConfig.addConfigValue("namedRoleCheck.class", NamedCheck.class.getName());
        Class<? extends Annotation> checkClass = coreConfiguration.getNamedRoleCheckClass();
        assertThat(checkClass).isNotNull();
    }

    @Test
    public void getNamedRoleCheckClass_wrongClass() {
        TestConfig.addConfigValue("namedRoleCheck.class", "some.unknown.class");
        Class<? extends Annotation> checkClass = coreConfiguration.getNamedRoleCheckClass();
        assertThat(checkClass).isNull();

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).isNotEmpty();
    }

    @Test
    public void getNamedRoleClass() {
        TestConfig.addConfigValue("namedRole.class", DemoNamedRole.class.getName());
        Class<? extends NamedRole> roleClass = coreConfiguration.getNamedRoleClass();
        assertThat(roleClass).isNotNull();
    }

    @Test
    public void getNamedRoleClass_wrongClass() {
        TestConfig.addConfigValue("namedRole.class", "someWrongClass");
        Class<? extends NamedRole> roleClass = coreConfiguration.getNamedRoleClass();
        assertThat(roleClass).isNull();

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).isNotEmpty();
    }
}