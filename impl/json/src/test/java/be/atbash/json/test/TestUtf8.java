/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.json.test;

import be.atbash.json.JSONObject;
import be.atbash.json.JSONValue;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class TestUtf8 {
    // Sinhalese language
    private static String[] nonLatinTexts = new String[]{"සිංහල ජාතිය", "日本語", "Русский", "فارسی", "한국어", "Հայերեն", "हिन्दी", "עברית", "中文", "አማርኛ", "മലയാളം",
            "ܐܬܘܪܝܐ", "მარგალური"};

    @Test
    public void testString() {
        for (String nonLatinText : nonLatinTexts) {
            String s = "{\"key\":\"" + nonLatinText + "\"}";
            JSONObject obj = (JSONObject) JSONValue.parse(s);
            String v = (String) obj.get("key"); // result is incorrect
            assertEquals(v, nonLatinText);
        }
    }

}
