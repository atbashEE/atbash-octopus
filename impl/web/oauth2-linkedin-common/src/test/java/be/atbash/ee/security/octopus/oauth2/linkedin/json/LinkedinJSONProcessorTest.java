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
package be.atbash.ee.security.octopus.oauth2.linkedin.json;

import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import javax.json.Json;
import javax.json.JsonObjectBuilder;

import static org.assertj.core.api.Assertions.assertThat;

public class LinkedinJSONProcessorTest {

    private LinkedinJSONProcessor processor = new LinkedinJSONProcessor();

    private TestLogger logger = TestLoggerFactory.getTestLogger(LinkedinJSONProcessor.class);

    @AfterEach
    public void clearLoggers() {
        TestLoggerFactory.clear();
    }

    @Test
    public void extractLinkedinUser() {
        JsonObjectBuilder builder = Json.createObjectBuilder();

        builder.add("id", "1234567");
        builder.add("emailAddress", "info@atbash.be");

        builder.add("lastName", "Atbash");
        builder.add("firstName", "Test");
        builder.add("publicProfileUrl", "http://atbash.be/");
        builder.add("pictureUrl", "http://atbash.be/logo.png");

        builder.add("custom1", "value1");
        builder.add("custom2", "value2");

        OAuth2UserToken token = processor.extractLinkedinUser(builder.build().toString());
        assertThat(token).isNotNull();
        assertThat(token.getId()).isEqualTo("1234567");
        assertThat(token.getEmail()).isEqualTo("info@atbash.be");
        assertThat(token.isVerifiedEmail()).isFalse();
        assertThat(token.getFullName()).isEqualTo("Atbash Test");
        assertThat(token.getLink()).isEqualTo("http://atbash.be/");
        assertThat(token.getPicture()).isEqualTo("http://atbash.be/logo.png");

        assertThat(token.getUserInfo().keySet()).contains("custom1", "custom2");
        assertThat(token.getUserInfo().keySet()).containsOnly("firstName", "lastName", "gender", "domain", "custom1", "custom2", "locale", "email", "picture");

    }

    @Test
    public void extractLinkedinUser_minimal() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("id", "1234567");
        builder.add("emailAddress", "info@atbash.be");

        OAuth2UserToken token = processor.extractLinkedinUser(builder.build().toString());
        assertThat(token).isNotNull();
        assertThat(token.getId()).isEqualTo("1234567");
        assertThat(token.getEmail()).isEqualTo("info@atbash.be");

        assertThat(token.getUserInfo().keySet()).containsOnly("firstName", "lastName", "gender", "domain", "locale", "email", "picture");

    }

    @Test
    public void extractLinkedin_error() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("error", "invalid authentication");

        Assertions.assertThrows(UnauthenticatedException.class, () ->
                processor.extractLinkedinUser(builder.build().toString()));

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Received following response from LinkedIn token resolving \n{\"error\":\"invalid authentication\"}");

    }
}
