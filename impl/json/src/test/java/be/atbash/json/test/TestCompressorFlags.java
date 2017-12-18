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
import be.atbash.json.style.JSONStyle;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

/**
 * Test all Compression Styles
 *
 * @author Uriel Chemouni &lt;uchemouni@gmail.com&gt;
 */
public class TestCompressorFlags {

    @Test
    public void testProtect() {
        String nCompress = "{\"k\":\"value\"}";

        JSONObject obj = (JSONObject) JSONValue.parse(nCompress);

        // test DEFAULT
        String r = obj.toJSONString();
        assertEquals(nCompress, r);

    }


}
