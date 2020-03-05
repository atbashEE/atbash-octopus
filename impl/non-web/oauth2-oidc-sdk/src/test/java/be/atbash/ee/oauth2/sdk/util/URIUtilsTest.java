/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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


import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URISyntaxException;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the URI utility methods.
 */
public class URIUtilsTest  {

	@Test
	public void testGetBaseURISame()
		throws URISyntaxException {

		URI uri = new URI("http://client.example.com:8080/endpoints/openid/connect/cb");

		URI baseURI = URIUtils.getBaseURI(uri);

		assertThat(baseURI.toString()).isEqualTo("http://client.example.com:8080/endpoints/openid/connect/cb");
	}

	@Test
	public void testGetBaseURITrim()
		throws URISyntaxException {

		URI uri = new URI("http://client.example.com:8080/endpoints/openid/connect/cb?param1=one&param2=two");

		URI baseURI = URIUtils.getBaseURI(uri);

		assertThat(baseURI.toString()).isEqualTo("http://client.example.com:8080/endpoints/openid/connect/cb");
	}

	@Test
	public void testRemoveTrailingSlash() {
		
		URI uri = URI.create("https://example.com/");
		
		assertThat(URIUtils.removeTrailingSlash(uri).toString()).isEqualTo("https://example.com");
	}

	@Test
	public void testRemoveTrailingSlash_notFound() {
		
		URI uri = URI.create("https://example.com");
		
		assertThat(URIUtils.removeTrailingSlash(uri).toString()).isEqualTo("https://example.com");
	}

	@Test
	public void testStripQueryString() {
		
		// Null safe
		assertThat(URIUtils.stripQueryString(null)).isNull();
		
		URI out = URIUtils.stripQueryString(URI.create("https://client.example.com:8080/endpoints/openid/connect/cb?param1=one&param2=two#fragment"));
		assertThat(out.toString()).isEqualTo("https://client.example.com:8080/endpoints/openid/connect/cb#fragment");
		
		out = URIUtils.stripQueryString(URI.create("https://c2id.com:8080/login?param1=one&param2=two"));
		assertThat(out.toString()).isEqualTo("https://c2id.com:8080/login");
	}
}
