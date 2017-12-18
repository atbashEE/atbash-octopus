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
package be.atbash.json.testMapping;

import be.atbash.json.JSONValue;
import net.minidev.asm.BeansAccessConfig;
import org.junit.Test;

import java.text.SimpleDateFormat;
import java.util.Date;

import static org.junit.Assert.assertEquals;

public class TestAdvancedMapper {
    static SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");

    @Test
    public void testCustomBean() {
        BeansAccessConfig.addTypeMapper(Object.class, MyLocalConverterot.class);
        String s = "{'val':2,'date':'19/04/2010'}";
        TestBean r = JSONValue.parse(s, TestBean.class);
        assertEquals("19/04/2010", sdf.format(r.date));
    }

    public static class TestBean {
        public int val;
        public Date date;
    }

    public static class MyLocalConverterot {

        public static Date fromString(Object text) throws Exception {
            if (text == null) {
                return null;
            }
            synchronized (sdf) {
                return sdf.parse(text.toString());
            }
        }
    }
}
