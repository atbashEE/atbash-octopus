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
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the audience class.
 */
public class AudienceTest  {

	@Test
	public void testToAudienceList() {

		Audience audience = new Audience("http://client.com");

		List<Audience> audienceList = audience.toSingleAudienceList();

		assertThat(audienceList.get(0).getValue()).isEqualTo("http://client.com");
		assertThat(audienceList).hasSize(1);
	}

	@Test
	public void testURIConstructor() {

		URI uri = URI.create("https://c2id.com");
		Audience aud = new Audience(uri);
		assertThat(aud.getValue()).isEqualTo(uri.toString());
		assertThat(aud.equals(new Audience("https://c2id.com"))).isTrue();
	}

	@Test
	public void testClientIDConstructor() {

		ClientID clientID = new ClientID("123");
		Audience aud = new Audience(clientID);
		assertThat(aud.getValue()).isEqualTo(clientID.toString());
		assertThat(aud.equals(new Audience("123"))).isTrue();
	}

	@Test
	public void testToStringListSingle() {

		assertThat(Audience.toStringList((Audience)null)).isNull();

		assertThat(Audience.toStringList(new Audience("A")).get(0)).isEqualTo("A");
		assertThat(Audience.toStringList(new Audience("A"))).hasSize(1);
	}

	@Test
	public void testToStringList() {

		assertThat(Audience.toStringList((List<Audience>)null)).isNull();

		assertThat(Audience.toStringList(Arrays.asList(new Audience("A"), new Audience("B"))).get(0)).isEqualTo("A");
		assertThat(Audience.toStringList(Arrays.asList(new Audience("A"), new Audience("B"))).get(1)).isEqualTo("B");
		assertThat(Audience.toStringList(Arrays.asList(new Audience("A"), new Audience("B")))).hasSize(2);
	}

	@Test
	public void testFromStringList() {

		assertThat(Audience.create((List<String>)null)).isNull();

		assertThat(Audience.create(Arrays.asList("A", "B")).get(0)).isEqualTo(new Audience("A"));
		assertThat(Audience.create(Arrays.asList("A", "B")).get(1)).isEqualTo(new Audience("B"));
		assertThat(Audience.create(Arrays.asList("A", "B"))).hasSize(2);
	}

	@Test
	public void testMatchesAny() {

		assertThat(Audience.matchesAny(Audience.create("A"), Audience.create("A"))).isTrue();
		assertThat(Audience.matchesAny(Audience.create("A", "B"), Audience.create("A"))).isTrue();
		assertThat(Audience.matchesAny(Audience.create("A"), Audience.create("A", "B"))).isTrue();
		assertThat(Audience.matchesAny(Audience.create("A"), Audience.create("B"))).isFalse();
		assertThat(Audience.matchesAny(Audience.create("B"), Audience.create("A"))).isFalse();
		assertThat(Audience.matchesAny(Audience.create("B", "B"), Audience.create("A", "A"))).isFalse();
		assertThat(Audience.matchesAny(null, Audience.create("A", "A"))).isFalse();
		assertThat(Audience.matchesAny(Audience.create("A", "A"), null)).isFalse();
		assertThat(Audience.matchesAny(null, null)).isFalse();
	}
}
