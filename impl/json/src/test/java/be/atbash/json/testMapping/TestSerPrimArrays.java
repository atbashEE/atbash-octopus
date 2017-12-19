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
import org.junit.Before;
import org.junit.Test;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import static org.junit.Assert.assertEquals;

public class TestSerPrimArrays {
    private SimpleDateFormat sdf;

    private String testDateString;
    private Date testDate;

    @Before
    public void setup() throws ParseException {
        sdf = new SimpleDateFormat("dd/MM/yyyy");
        testDateString = "12/01/2010";
        testDate = sdf.parse(testDateString);
    }

    @Test
    public void testDate() {
        String s = "'" + testDateString + "'";
        Date dt = JSONValue.parse(s, Date.class);
        assertEquals(dt, this.testDate);
    }

    public void testDtObj() throws Exception {
        String s = "{date:'" + testDateString + "'}";
        ADate dt = JSONValue.parse(s, ADate.class);
        assertEquals(dt.date, this.testDate);
    }

    public static class ADate {
        public Date date;
    }

}
