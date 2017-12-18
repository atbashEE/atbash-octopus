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

import static org.junit.Assert.assertEquals;

public class TestDate  {

	@Test
	public void testBooleans()  {
		String s = "[true,true,false]";
		boolean[] bs = new boolean[] { true, true, false };
		String s2 = JSONValue.toJSONString(bs);
		assertEquals(s, s2);
	}

	@Test
	public void testInts()  {
		String s = "[1,2,3]";
		int[] bs = new int[] { 1, 2, 3 };
		String s2 = JSONValue.toJSONString(bs);
		assertEquals(s, s2);
	}

}
