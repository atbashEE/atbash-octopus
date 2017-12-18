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

public class TestInvalidNumber {

    @Test
    public void testF1() {
        String test = "51e88";
        JSONObject o = new JSONObject();
        o.put("a", test);
        String comp = JSONValue.toJSONString(o);
        assertEquals("{\"a\":\"51e88\"}", comp);

        o = JSONValue.parse(comp, JSONObject.class);
        assertEquals(o.get("a"), test);
    }

    @Test
    public void testF2() {
        String test = "51e+88";
        JSONObject o = new JSONObject();
        o.put("a", test);
        String comp = JSONValue.toJSONString(o);
        assertEquals("{\"a\":\"51e+88\"}", comp);

        o = JSONValue.parse(comp, JSONObject.class);
        assertEquals(o.get("a"), test);
    }

    @Test
    public void testF3() {
        String test = "51e-88";
        JSONObject o = new JSONObject();
        o.put("a", test);
        String comp = JSONValue.toJSONString(o);
        assertEquals("{\"a\":\"51e-88\"}", comp);

        o = JSONValue.parse(comp, JSONObject.class);
        assertEquals(o.get("a"), test);
    }

    @Test
    public void testF4() {
        String test = "51ee88";
        JSONObject o = new JSONObject();
        o.put("a", test);
        String comp = JSONValue.toJSONString(o);
        assertEquals("{\"a\":\"51ee88\"}", comp);

        o = JSONValue.parse(comp, JSONObject.class);
        assertEquals(o.get("a"), test);
    }

}
