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

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;


public class ResourceUtilsTest  {

	@Test
	public void testIsValidResourceURI_positive() {
		
		assertThat(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com"))).isTrue();
		assertThat(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/"))).isTrue();
		assertThat(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com:8080/"))).isTrue();
		assertThat(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/api"))).isTrue();
		assertThat(ResourceUtils.isValidResourceURI(URI.create("resource://rs1.com/api/v1"))).isTrue();
	}

	@Test
	public void testIsValidResourceURI_negative() {
		
		assertThat(ResourceUtils.isValidResourceURI(URI.create("https:///path"))).isFalse();
		assertThat(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/api?query"))).isFalse();
		assertThat(ResourceUtils.isValidResourceURI(URI.create("https://rs1.com/api#fragment"))).isFalse();
	}
}
