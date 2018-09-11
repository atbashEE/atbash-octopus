/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.oauth2.info;

import be.atbash.ee.security.octopus.oauth2.OAuth2UserToken;
import be.atbash.json.JSONObject;
import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class OAuth2UserInfoProcessorTest {

    private OAuth2UserInfoProcessor processor = new OAuth2UserInfoProcessor() {
    };

    @Test
    public void processJSON() {
        OAuth2UserToken oAuth2User = new OAuth2UserToken();

        Map<String, Object> data = new HashMap<>();
        data.put("key1", "value1");
        data.put("key2", 123L);
        data.put("key3", new RGB(25, 73, 154));
        JSONObject json = new JSONObject(data);
        processor.processJSON(oAuth2User, json, Collections.<String>emptyList());

        assertThat(oAuth2User.getUserInfo()).containsKeys("key1", "key2", "key3");
        assertThat(oAuth2User.getUserInfo().get("key1")).isEqualTo("value1");
        assertThat(oAuth2User.getUserInfo().get("key2")).isEqualTo(123L);
        assertThat(oAuth2User.getUserInfo().get("key3")).isEqualTo("RGB{r=25, g=73, b=154}"); // The toString value
    }

    @Test
    public void processJSON_excludeKeys() {
        OAuth2UserToken oAuth2User = new OAuth2UserToken();

        Map<String, Object> data = new HashMap<>();
        data.put("key1", "value1");
        data.put("key2", 123L);

        JSONObject json = new JSONObject(data);
        List<String> excludedKeys = Collections.singletonList("key1");
        processor.processJSON(oAuth2User, json, excludedKeys);

        assertThat(oAuth2User.getUserInfo()).doesNotContainKeys("key1");
    }

    @Test
    public void optString() {
        JSONObject json = new JSONObject();
        assertThat(processor.optString(json, "key")).isNull();
    }

    @Test
    public void optString_withValue() {
        Map<String, Object> data = new HashMap<>();
        data.put("key", "value");

        JSONObject json = new JSONObject(data);
        assertThat(processor.optString(json, "key")).isEqualTo("value");
    }

    private static class RGB {
        private int r;
        private int g;
        private int b;

        public RGB(int r, int g, int b) {
            this.r = r;
            this.g = g;
            this.b = b;
        }

        @Override
        public String toString() {
            return "RGB{" +
                    "r=" + r +
                    ", g=" + g +
                    ", b=" + b +
                    '}';
        }
    }
}