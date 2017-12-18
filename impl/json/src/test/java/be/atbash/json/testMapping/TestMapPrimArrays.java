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
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertEquals;

public class TestMapPrimArrays {

    @Test
    public void testInts() {
        String s = "[1,2,3]";
        int[] r = JSONValue.parse(s, int[].class);
        assertEquals(3, r[2]);
    }

    @Test
    public void testIntss() {
        String s = "[[1],[2],[3,4]]";
        int[][] r = JSONValue.parse(s, int[][].class);
        assertEquals(3, r[2][0]);
        assertEquals(4, r[2][1]);
    }

    @Test
    public void testLongs() {
        String s = "[1,2,3]";
        long[] r = JSONValue.parse(s, long[].class);
        assertEquals(3, r[2]);
    }

    @Test
    public void testFloat() {
        String s = "[1.2,22.4,3.14]";
        float[] r = JSONValue.parse(s, float[].class);
        assertThat(r[2]).isEqualTo(3.14F);
    }

    @Test
    public void testDouble() {
        String s = "[1.2,22.4,3.14]";
        double[] r = JSONValue.parse(s, double[].class);
        assertThat(r[2]).isEqualTo(3.14D);
    }

    @Test
    public void testBooleans() {
        String s = "[true,true,false]";
        boolean[] r = JSONValue.parse(s, boolean[].class);
        assertEquals(true, r[1]);
        assertEquals(false, r[2]);
    }
}
