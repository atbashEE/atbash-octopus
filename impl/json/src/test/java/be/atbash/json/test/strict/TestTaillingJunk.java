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

import be.atbash.json.JSONObject;
import be.atbash.json.parser.JSONParser;
import be.atbash.json.parser.ParseException;
import be.atbash.json.test.MustThrows;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * @since 1.0.7
 */
public class TestTaillingJunk {

    @Test
    public void testTaillingSpace() {
        String s = "{\"t\":0}   ";
        MustThrows.testInvalidJson(s, JSONParser.MODE_STRICTEST, ParseException.ERROR_UNEXPECTED_TOKEN);

        s = "{\"t\":0}   ";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE).parse(s);
        assertEquals(o.get("t"), 0);
    }

    @Test
    public void testTaillingSpace2() {
        String s = "{\"t\":0}   \r\n ";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE).parse(s);
        assertEquals(o.get("t"), 0);
    }

    @Test
    public void testTaillingData() {
        String s = "{\"t\":0}  0";
        MustThrows.testInvalidJson(s, JSONParser.MODE_STRICTEST, ParseException.ERROR_UNEXPECTED_TOKEN, null);
    }

    @Test
    public void testTaillingDataPermisive() {
        String s = "{\"t\":0}  0";
        JSONObject o = (JSONObject) new JSONParser(JSONParser.MODE_PERMISSIVE).parse(s);
        assertEquals(o.get("t"), 0);
    }

    @Test
    public void testTaillingDataWithSpaceAllowed() {
        String s = "{\"t\":0}{";
        MustThrows.testInvalidJson(s, JSONParser.MODE_STRICTEST | JSONParser.ACCEPT_TAILLING_SPACE, ParseException.ERROR_UNEXPECTED_TOKEN);
    }
}
