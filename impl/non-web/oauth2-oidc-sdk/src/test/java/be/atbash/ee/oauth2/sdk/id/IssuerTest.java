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
package be.atbash.ee.oauth2.sdk.id;


import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the issuer identifier class.
 */
public class IssuerTest  {


	@Test
	public void testConstructor() {

		Issuer iss = new Issuer("https://c2id.com");

		assertThat(iss.getValue()).isEqualTo("https://c2id.com");
		assertThat(iss.toString()).isEqualTo("https://c2id.com");
	}

	@Test
	public void testStaticStringValidationMethods() {

		assertThat(Issuer.isValid("https://c2id.com/")).isTrue();
		assertThat(Issuer.isValid("https://c2id.com/oidc/")).isTrue();

		assertThat(Issuer.isValid((String)null)).isFalse();
		assertThat(Issuer.isValid("http://c2id.com")).isFalse();
		assertThat(Issuer.isValid("https://c2id.com?query=abc")).isFalse();
		assertThat(Issuer.isValid("https://c2id.com/oidc/#abc")).isFalse();
		assertThat(Issuer.isValid("https://c2id.com/oidc/?query=abc#abc")).isFalse();
		assertThat(Issuer.isValid("ftp://c2id.com/oidc/?query=abc#abc")).isFalse();
	}

	@Test
	public void testStaticIssuerValidationMethods() {

		assertThat(Issuer.isValid(new Issuer("https://c2id.com/"))).isTrue();
		assertThat(Issuer.isValid(new Issuer("https://c2id.com/oidc/"))).isTrue();

		assertThat(Issuer.isValid((Issuer)null)).isFalse();
		assertThat(Issuer.isValid(new Issuer("http://c2id.com"))).isFalse();
		assertThat(Issuer.isValid(new Issuer("https://c2id.com?query=abc"))).isFalse();
		assertThat(Issuer.isValid(new Issuer("https://c2id.com/oidc/#abc"))).isFalse();
		assertThat(Issuer.isValid(new Issuer("https://c2id.com/oidc/?query=abc#abc"))).isFalse();
		assertThat(Issuer.isValid(new Issuer("ftp://c2id.com/oidc/?query=abc#abc"))).isFalse();
	}

	@Test
	public void testStaticURIValidationMethods()
		throws URISyntaxException {

		assertThat(Issuer.isValid(new URI("https://c2id.com/"))).isTrue();
		assertThat(Issuer.isValid(new URI("https://c2id.com/oidc/"))).isTrue();

		assertThat(Issuer.isValid((URI)null)).isFalse();
		assertThat(Issuer.isValid(new URI("http://c2id.com"))).isFalse();
		assertThat(Issuer.isValid(new URI("https://c2id.com?query=abc"))).isFalse();
		assertThat(Issuer.isValid(new URI("https://c2id.com/oidc/#abc"))).isFalse();
		assertThat(Issuer.isValid(new URI("https://c2id.com/oidc/?query=abc#abc"))).isFalse();
		assertThat(Issuer.isValid(new URI("ftp://c2id.com/oidc/?query=abc#abc"))).isFalse();
	}

	@Test
	public void testInstanceValidation() {

		assertThat(new Issuer("https://c2id.com/").isValid()).isTrue();
		assertThat(new Issuer("https://c2id.com/oidc/").isValid()).isTrue();

		assertThat(new Issuer("http://c2id.com").isValid()).isFalse();
		assertThat(new Issuer("https://c2id.com?query=abc").isValid()).isFalse();
		assertThat(new Issuer("https://c2id.com/oidc/#abc").isValid()).isFalse();
		assertThat(new Issuer("https://c2id.com/oidc/?query=abc#abc").isValid()).isFalse();
		assertThat(new Issuer("ftp://c2id.com/oidc/?query=abc#abc").isValid()).isFalse();
	}

	@Test
	public void testURIConstructor() {

		assertThat(new Issuer(URI.create("https://c2id.com")).getValue()).isEqualTo("https://c2id.com");
		assertThat(new Issuer(URI.create("https://c2id.com")).equals(new Issuer("https://c2id.com"))).isTrue();
	}

	@Test
	public void testClientIDConstructor() {

		assertThat(new Issuer(new ClientID("123")).getValue()).isEqualTo("123");
		assertThat(new Issuer("123").equals(new Issuer(new ClientID("123")))).isTrue();
	}
}
