/*
 * oauth2-oidc-sdk
 *
 * Copyright 2012-2016, Connect2id Ltd and contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a copy of the
 * License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */

package be.atbash.ee.oauth2.sdk;


import org.junit.Test;

import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the scope class.
 */
public class ScopeTest {

	@Test
	public void testCopyConstructor() {

		Scope scope = new Scope(Scope.parse("read write"));
		assertThat(scope.contains("read"));
		assertThat(scope.contains("write"));
		assertThat(scope).hasSize(2);
	}

	@Test
	public void testCopyConstructorNull() {

		Scope scope = new Scope((Scope)null);
		assertThat(scope.isEmpty()).isTrue();
	}

	@Test
	public void testVarargConstructor() {

		Scope scope = new Scope(new Scope.Value("read"), new Scope.Value("write"));

		assertThat(scope).contains(new Scope.Value("read"));
		assertThat(scope).contains(new Scope.Value("write"));
		assertThat(scope).hasSize(2);
	}

	@Test
	public void testStringVarargConstructor() {

		Scope scope = new Scope("read", "write");

		assertThat(scope).contains(new Scope.Value("read"));
		assertThat(scope).contains(new Scope.Value("write"));
		assertThat(scope).hasSize(2);
	}

	@Test
	public void testRun() {

		Scope scope = new Scope();

		scope.add(new Scope.Value("read"));
		scope.add(new Scope.Value("write"));

		assertThat(scope).contains(new Scope.Value("read"));
		assertThat(scope.contains("read")).isTrue();
		assertThat(scope).contains(new Scope.Value("write"));
		assertThat(scope.contains("write")).isTrue();
		assertThat(scope).hasSize(2);

		assertThat(scope.contains(new Scope.Value("no-such-value"))).isFalse();
		assertThat(scope.contains("no-such-value")).isFalse();

		String out = scope.toString();

		System.out.println("Scope: " + out);
		
		assertThat(out).isEqualTo("read write");

		Scope scopeParsed = Scope.parse(out);

		assertThat(scope).contains(new Scope.Value("read"));
		assertThat(scope).contains(new Scope.Value("write"));
		assertThat(scopeParsed).hasSize(2);

		assertThat(scope.equals(scopeParsed)).isTrue();
	}

	@Test
	public void testListSerializationAndParsing() {
		
		Scope scope = Scope.parse("read write");
		
		List<String> list = scope.toStringList();
		
		assertThat(list.get(0)).isEqualTo("read");
		assertThat(list.get(1)).isEqualTo("write");
		assertThat(list).hasSize(2);
		
		assertThat(Scope.parse(list).toString()).isEqualTo("read write");
	}

	@Test
	public void testInequality() {

		Scope s1 = Scope.parse("read");
		Scope s2 = Scope.parse("write");

		assertThat(s1.equals(s2)).isFalse();
	}

	@Test
	public void testParseNullString() {

		assertThat(Scope.parse((String)null)).isNull();
	}

	@Test
	public void testParseNullCollection() {

		assertThat(Scope.parse((Collection<String>)null)).isNull();
	}

	@Test
	public void testParseEmptyString() {

		Scope s = Scope.parse("");

		assertThat(s).hasSize(0);
	}

	@Test
	public void testAddString() {

		Scope scope = new Scope();

		assertThat(scope.add("openid")).isTrue();
		assertThat(scope.contains("openid")).isTrue();
		assertThat(scope).hasSize(1);

		assertThat(scope.add("openid")).isFalse();
		assertThat(scope.contains("openid")).isTrue();
		assertThat(scope).hasSize(1);
	}

	@Test
	public void testParseCommaDelimited() {

		Scope scope = Scope.parse("read,write,admin");

		assertThat(scope.contains("read")).isTrue();
		assertThat(scope.contains("write")).isTrue();
		assertThat(scope.contains("admin")).isTrue();
		assertThat(scope).hasSize(3);
	}
}
