/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.oauth2.sdk.util;


import org.junit.Test;

import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;


public class MultivaluedMapUtilsTest  {
	
	@Test
	public void testToSingleValuedMap_null() {
		
		assertThat(MultivaluedMapUtils.toSingleValuedMap(null)).isNull();
	}

	@Test
	public void testToSingleValuedMap_oneEntry_singleValued_null() {
		
		Map<String, List<String>> in = new HashMap<>();
		in.put("a", Collections.singletonList((String)null));
		
		Map<String, String> out = MultivaluedMapUtils.toSingleValuedMap(in);
		assertThat(out.get("a")).isNull();
		assertThat(out).hasSize(1);
	}

	@Test
	public void testToSingleValuedMap_oneEntry_singleValued() {
		
		Map<String, List<String>> in = new HashMap<>();
		in.put("a", Collections.singletonList("1"));
		
		Map<String, String> out = MultivaluedMapUtils.toSingleValuedMap(in);
		assertThat(out.get("a")).isEqualTo("1");
		assertThat(out).hasSize(1);
	}

	@Test
	public void testToSingleValuedMap_oneEntry_twoValues() {
		
		Map<String, List<String>> in = new HashMap<>();
		in.put("a", Arrays.asList("1", "2"));
		
		Map<String, String> out = MultivaluedMapUtils.toSingleValuedMap(in);
		assertThat(out.get("a")).isEqualTo("1");
		assertThat(out).hasSize(1);
	}

	@Test
	public void testToSingleValuedMap_oneEntry_threeValues() {
		
		Map<String, List<String>> in = new HashMap<>();
		in.put("a", Arrays.asList("1", "2", "3"));
		
		Map<String, String> out = MultivaluedMapUtils.toSingleValuedMap(in);
		assertThat(out.get("a")).isEqualTo("1");
		assertThat(out).hasSize(1);
	}
}
