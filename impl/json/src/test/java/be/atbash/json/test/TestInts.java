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
import be.atbash.json.parser.JSONParser;
import be.atbash.json.parser.ParseException;
import org.junit.Test;

import java.math.BigDecimal;
import java.math.BigInteger;

import static org.junit.Assert.assertEquals;

public class TestInts {

    @Test
    public void testIntMax() {
        String s = "{t:" + Integer.MAX_VALUE + "}";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(s);
        assertEquals(o.get("t"), Integer.MAX_VALUE);
    }

    @Test
    public void testIntMin() {
        String s = "{t:" + Integer.MIN_VALUE + "}";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(s);
        assertEquals(o.get("t"), Integer.MIN_VALUE);
    }

    @Test
    public void testIntResult() {
        String s = "{\"t\":1}";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_RFC4627).parse(s);
        assertEquals(o.get("t"), 1);

        o = (JSONObject) new JSONParser(JSONParser.MODE_JSON_SIMPLE).parse(s);
        assertEquals(o.get("t"), 1L);

        o = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(s);
        assertEquals(o.get("t"), 1);
    }

    @Test
    public void testInt() {
        String s = "{t:90}";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(s);
        assertEquals(o.get("t"), 90);
    }

    @Test
    public void testIntNeg() {
        String s = "{t:-90}";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(s);
        assertEquals(o.get("t"), -90);
    }

    @Test
    public void testBigInt() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10; i++) {
            sb.append(Integer.MAX_VALUE);
        }
        String bigText = sb.toString();
        BigInteger big = new BigInteger(bigText, 10);
        String s = "{t:" + bigText + "}";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(s);
        assertEquals(o.get("t"), big);
    }

    @Test
    public void testBigDoubleInt() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10; i++) {
            sb.append(Integer.MAX_VALUE);
        }
        sb.append('.');
        for (int i = 0; i < 10; i++) {
            sb.append(Integer.MAX_VALUE);
        }

        String bigText = sb.toString();
        BigDecimal big = new BigDecimal(bigText);
        String s = "{\"t\":" + bigText + "}";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_RFC4627).parse(s);
        assertEquals(o.get("t"), big);
        o = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(s);
        assertEquals(o.get("t"), big);
    }

    @Test
    public void testjunkTaillingData()  {
        String s = "{\"t\":124}$ifsisg045";

        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_JSON_SIMPLE).parse(s);
        assertEquals(o.get("t"), 124L);

        MustThrows.testInvalidJson(s, JSONParser.MODE_RFC4627, ParseException.ERROR_UNEXPECTED_TOKEN);
        // o = (JSONObject) new JSONParser(JSONParser.MODE_RFC4627).parse(s);
        // assertEquals(o.get("t"), 124);

        o = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(s);
        assertEquals(o.get("t"), 124);
    }
}
