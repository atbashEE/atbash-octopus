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

import be.atbash.json.JSONValue;
import be.atbash.json.parser.ParseException;
import be.atbash.json.test.MustThrows;
import org.junit.Test;

public class TestExcessiveComma {

    @Test
    public void testExcessiveComma1A() {
        String s = "[1,2,,3]";
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_CHAR);
        JSONValue.parse(s);
    }

    @Test
    public void testExcessiveComma2A() {
        String s = "[1,2,]";
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_CHAR);
        JSONValue.parse(s);
    }

    @Test
    public void testExcessiveComma3A() {
        String s = "[,]";
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_CHAR);
        JSONValue.parse(s);
    }

    @Test
    public void testExcessiveComma4A() {
        String s = "[,5]";
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_CHAR);
        JSONValue.parse(s);
    }

    @Test
    public void testExcessiveComma1O() {
        String s = "{\"a\":1,,\"b\":1}";
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_CHAR);
        JSONValue.parse(s);
    }

    @Test
    public void testExcessiveComma2O() {
        String s = "{\"a\":1,}";
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_CHAR);
        JSONValue.parse(s);
    }

    @Test
    public void testExcessiveComma3O() {
        String s = "{,}";
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_CHAR);
        JSONValue.parse(s);
    }
}
