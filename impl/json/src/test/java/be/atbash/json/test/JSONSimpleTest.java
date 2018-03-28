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
package be.atbash.json.test;

import be.atbash.json.JSONArray;
import be.atbash.json.parser.JSONParser;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class JSONSimpleTest {

    @Test
    public void testLong() {
        String s = "[1]";
        JSONParser p = new JSONParser(JSONParser.MODE_JSON_SIMPLE);
        JSONArray array = (JSONArray) p.parse(s);
        assertEquals(1L, array.get(0));
        // FIXME, wrong test on the type
    }

    @Test
    public void testDefault() {
        String s = "[1]";
        JSONParser p = new JSONParser(JSONParser.MODE_PERMISSIVE);
        JSONArray array = (JSONArray) p.parse(s);
        assertEquals(1, array.get(0));
        // FIXME, wrong test on the type
    }
}
