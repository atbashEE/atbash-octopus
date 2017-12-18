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

import be.atbash.json.parser.JSONParser;
import be.atbash.json.parser.ParseException;
import junit.framework.TestCase;

public class MustThrows {

    public static void testStrictInvalidJson(String json, int execptionType) {
        testStrictInvalidJson(json, execptionType, null);
    }

    public static void testStrictInvalidJson(String json, int execptionType, Class<?> cls) {
        testInvalidJson(json, JSONParser.MODE_RFC4627, execptionType, cls);
    }

    public static void testInvalidJson(String json, int permissifMode, int execptionType) {
        testInvalidJson(json, permissifMode, execptionType, null);
    }

    public static void testInvalidJson(String json, int permissifMode, int execptionType, Class<?> cls) {
        JSONParser p = new JSONParser(permissifMode);
        try {
            if (cls == null) {
                p.parse(json);
            } else {
                p.parse(json, cls);
            }
            TestCase.assertFalse("Exception Should Occur parsing:" + json, true);
        } catch (ParseException e) {
            if (execptionType == -1) {
                execptionType = e.getErrorType();
            }
            TestCase.assertEquals(execptionType, e.getErrorType());
        }
    }

}
