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
import be.atbash.json.parser.JSONParser;
import be.atbash.json.parser.ParseException;
import be.atbash.json.test.MustThrows;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Test control charaters
 *
 * @author uriel
 */
public class TestSpecialChar {

    @Test
    public void testSpecial127() {
        String s127 = String.format("%c", 127);
        String s = String.format("[\"%c\"]", 127);
        MustThrows.testInvalidJson(s, JSONParser.MODE_STRICTEST, ParseException.ERROR_UNEXPECTED_CHAR);

        JSONArray o = (JSONArray) new JSONParser(JSONParser.MODE_RFC4627).parse(s);
        assertEquals(o.get(0), s127);
    }

    @Test
    public void testSpecial31() {
        String s = String.format("[\"%c\"]", 31);
        MustThrows.testInvalidJson(s, JSONParser.MODE_STRICTEST, ParseException.ERROR_UNEXPECTED_CHAR);
    }

}
