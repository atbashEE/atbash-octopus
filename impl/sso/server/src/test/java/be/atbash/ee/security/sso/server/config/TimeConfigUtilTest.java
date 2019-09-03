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

import com.google.common.collect.ImmutableList;
import org.junit.After;
import org.junit.Test;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.LoggingEvent;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;

public class TimeConfigUtilTest {

    private TestLogger logger = TestLoggerFactory.getTestLogger(TimeConfigUtil.class);

    @After
    public void teardown() {
        TestLoggerFactory.clear();
    }

    @Test
    public void getSecondsFromConfigPattern_hours() {

        int result = TimeConfigUtil.getSecondsFromConfigPattern("8h", "10h", "SSO.cookie.timetolive");
        assertThat(result).isEqualTo(8 * 3600);
    }

    @Test
    public void getSecondsFromConfigPattern_days() {

        int result = TimeConfigUtil.getSecondsFromConfigPattern("12d", "10h", "SSO.cookie.timetolive");
        assertThat(result).isEqualTo(12 * 24 * 3600);
    }

    @Test
    public void getSecondsFromConfigPattern_minutes() {

        int result = TimeConfigUtil.getSecondsFromConfigPattern("12m", "1h", "SSO.access.token.timetolive");
        assertThat(result).isEqualTo(12 * 60);
    }

    @Test
    public void getSecondsFromConfigPattern_seconds() {

        int result = TimeConfigUtil.getSecondsFromConfigPattern("1s", "1h", "SSO.access.token.timetolive");
        assertThat(result).isEqualTo(1);
    }

    @Test
    public void getSecondsFromConfigPattern_default() {

        int result = TimeConfigUtil.getSecondsFromConfigPattern(null, "10h", "SSO.cookie.timetolive");
        assertThat(result).isEqualTo(10 * 3600);
    }

    @Test
    public void getSecondsFromConfigPattern_wrongValue() {
        int result = TimeConfigUtil.getSecondsFromConfigPattern("JUnit", "10h", "SSO.cookie.timetolive");
        assertThat(result).isEqualTo(10 * 3600); // Default Value

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).hasSize(1);
        assertThat(events.get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(events.get(0).getMessage()).isEqualTo("Invalid configuration value for SSO.cookie.timetolive = JUnit. Using default of 10h");

    }

    @Test
    public void getSecondsFromConfigPattern_Zero() {
        int result = TimeConfigUtil.getSecondsFromConfigPattern("0h", "10h", "SSO.cookie.timetolive");
        assertThat(result).isEqualTo(10 * 3600); // Default Value

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).hasSize(1);
        assertThat(events.get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(events.get(0).getMessage()).isEqualTo("Invalid configuration value for SSO.cookie.timetolive = 0h. Using default of 10h");

    }

    @Test
    public void getSecondsFromConfigPattern_negative() {
        int result = TimeConfigUtil.getSecondsFromConfigPattern("-1h", "10h", "SSO.cookie.timetolive");
        assertThat(result).isEqualTo(10 * 3600); // Default Value

        ImmutableList<LoggingEvent> events = logger.getLoggingEvents();
        assertThat(events).hasSize(1);
        assertThat(events.get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(events.get(0).getMessage()).isEqualTo("Invalid configuration value for SSO.cookie.timetolive = -1h. Using default of 10h");
    }

}