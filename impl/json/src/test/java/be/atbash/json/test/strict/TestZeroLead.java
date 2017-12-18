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
package be.atbash.json.test.strict;

import be.atbash.json.JSONArray;
import be.atbash.json.JSONObject;
import be.atbash.json.JSONValue;
import be.atbash.json.parser.JSONParser;
import be.atbash.json.parser.ParseException;
import be.atbash.json.test.MustThrows;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @since 1.0.7
 */
public class TestZeroLead {

    @Test
    public void test0O() {
        String s = "{\"t\":0}";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_RFC4627).parse(s);
        assertEquals(o.get("t"), 0);
        JSONValue.parse(s);
    }

    @Test
    public void test0A() {
        String s = "[0]";
        JSONArray o = (JSONArray) new JSONParser(JSONParser.MODE_RFC4627).parse(s);
        assertEquals(o.get(0), 0);
        JSONValue.parse(s);
    }

    @Test
    public void test0Float() {
        String s = "[00.0]";
        // strict
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_LEADING_0);
        // PERMISIVE
        JSONValue.parse(s);
    }

    @Test
    public void test01Float() {
        String s = "[01.0]";
        // strict
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_LEADING_0);
        // PERMISIVE
        JSONValue.parse(s);
    }

    @Test
    public void test00001() {
        String s = "{\"t\":00001}";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(s);
        assertEquals(o.get("t"), 1);
        JSONValue.parse(s);
    }

    @Test
    public void test00001Strict() {
        String s = "{\"t\":00001}";
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_LEADING_0);
        JSONValue.parse(s);
    }

}
