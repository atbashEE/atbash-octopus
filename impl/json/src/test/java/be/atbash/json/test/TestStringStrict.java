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

import be.atbash.json.parser.ParseException;
import junit.framework.TestCase;
import org.junit.Test;

public class TestStringStrict  {

    @Test
    public void testS1()  {
        String text = "My Test";
        String s = "{t:\"" + text + "\"}";
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_TOKEN);
    }

    @Test
    public void testSEscape()  {
        String text2 = "My\\r\\nTest";
        String s = "{\"t\":'" + text2 + "'}";
        MustThrows.testStrictInvalidJson(s, ParseException.ERROR_UNEXPECTED_CHAR);
    }
}
