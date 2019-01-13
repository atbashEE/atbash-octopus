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
package be.atbash.ee.security.octopus.oauth2.linkedin.json;

import be.atbash.ee.security.octopus.authz.UnauthenticatedException;
import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.json.JSONObject;
import org.junit.After;
import org.junit.Test;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;

public class LinkedinJSONProcessorTest {

    private LinkedinJSONProcessor processor = new LinkedinJSONProcessor();

    private TestLogger logger = TestLoggerFactory.getTestLogger(LinkedinJSONProcessor.class);

    @After
    public void clearLoggers() {
        TestLoggerFactory.clear();
    }

    @Test
    public void extractLinkedinUser() {
        JSONObject data = new JSONObject();

        data.put("id", "1234567");
        data.put("emailAddress", "info@atbash.be");

        data.put("lastName", "Atbash");
        data.put("firstName", "Test");
        data.put("publicProfileUrl", "http://atbash.be/");
        data.put("pictureUrl", "http://atbash.be/logo.png");

        data.put("custom1", "value1");
        data.put("custom2", "value2");

        OAuth2UserToken token = processor.extractLinkedinUser(data.toJSONString());
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
        JSONObject data = new JSONObject();
        data.put("id", "1234567");
        data.put("emailAddress", "info@atbash.be");

        OAuth2UserToken token = processor.extractLinkedinUser(data.toJSONString());
        assertThat(token).isNotNull();
        assertThat(token.getId()).isEqualTo("1234567");
        assertThat(token.getEmail()).isEqualTo("info@atbash.be");

        assertThat(token.getUserInfo().keySet()).containsOnly("firstName", "lastName", "gender", "domain", "locale", "email", "picture");

    }

    @Test(expected = UnauthenticatedException.class)
    public void extractLinkedin_error() {
        JSONObject data = new JSONObject();
        data.put("error", "invalid authentication");

        try {
            processor.extractLinkedinUser(data.toJSONString());
        } finally {
            assertThat(logger.getLoggingEvents()).hasSize(1);
            assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Received following response from LinkedIn token resolving \n{\"error\":\"invalid authentication\"}");
        }
    }
}
