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

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;

public class TestBigValue {
    String bigStr = "12345678901234567890123456789";

    /**
     * test BigDecimal serialization
     */
    @Test
    public void testBigDecimal() {
        HashMap<String, Object> map = new HashMap<String, Object>();
        BigDecimal bigDec = new BigDecimal(bigStr + "." + bigStr);
        map.put("big", bigDec);
        String test = JSONValue.toJSONString(map);
        String result = "{\"big\":" + bigStr + "." + bigStr + "}";
        assertEquals(result, test);
        JSONObject obj = (JSONObject) JSONValue.parse(test);
        assertEquals(bigDec, obj.get("big"));
        assertEquals(bigDec.getClass(), obj.get("big").getClass());
    }

    /**
     * test BigInteger serialization
     */
    @Test
    public void testBigInteger() {
        HashMap<String, Object> map = new HashMap<String, Object>();
        BigInteger bigInt = new BigInteger(bigStr);
        map.put("big", bigInt);
        String test = JSONValue.toJSONString(map);
        String result = "{\"big\":" + bigStr + "}";
        assertEquals(result, test);
        JSONObject obj = (JSONObject) JSONValue.parse(test);
        assertEquals(bigInt, obj.get("big"));
        assertEquals(bigInt.getClass(), obj.get("big").getClass());
    }
}
