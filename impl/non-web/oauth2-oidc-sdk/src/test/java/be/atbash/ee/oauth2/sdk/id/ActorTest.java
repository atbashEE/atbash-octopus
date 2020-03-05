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
package be.atbash.ee.oauth2.sdk.id;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import org.junit.jupiter.api.Test;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

import static org.assertj.core.api.Assertions.assertThat;

public class ActorTest  {
	
	@Test
	public void testMinimalConstructor()
		throws OAuth2JSONParseException {

		Actor actor = new Actor(new Subject("claire"));
		assertThat(actor.getSubject().getValue()).isEqualTo("claire");
		assertThat(actor.getIssuer()).isNull();
		assertThat(actor.getParent()).isNull();

		JsonObject jsonObject = actor.toJSONObject();
		assertThat(jsonObject.getString("sub")).isEqualTo("claire");
		assertThat(jsonObject).hasSize(1);

		actor = Actor.parse(jsonObject);
		assertThat(actor.getSubject().getValue()).isEqualTo("claire");
		assertThat(actor.getIssuer()).isNull();
		assertThat(actor.getParent()).isNull();

		// top-level JSON object
		JsonObjectBuilder topLevel = Json.createObjectBuilder();
		topLevel.add("act", actor.toJSONObject());

		actor = Actor.parseTopLevel(topLevel.build());
		assertThat(actor.getSubject().getValue()).isEqualTo("claire");
		assertThat(actor.getIssuer()).isNull();
		assertThat(actor.getParent()).isNull();
	}

	@Test
	public void testFullConstructor()
		throws OAuth2JSONParseException {

		Actor parent = new Actor(new Subject("cindy"));

		Actor actor = new Actor(new Subject("claire"), new Issuer("https://openid.c2id.com"), parent);
		assertThat(actor.getSubject().getValue()).isEqualTo("claire");
		assertThat(actor.getIssuer().getValue()).isEqualTo("https://openid.c2id.com");
		assertThat(actor.getParent()).isEqualTo(parent);

		JsonObject jsonObject = actor.toJSONObject();
		assertThat(jsonObject.getString("sub")).isEqualTo("claire");
		assertThat(jsonObject.getString("iss")).isEqualTo("https://openid.c2id.com");
		assertThat(jsonObject.getJsonObject("act").getString("sub")).isEqualTo("cindy");
		assertThat(jsonObject).hasSize(3);

		actor = Actor.parse(jsonObject);
		assertThat(actor.getSubject().getValue()).isEqualTo("claire");
		assertThat(actor.getIssuer().getValue()).isEqualTo("https://openid.c2id.com");
		assertThat(actor.getParent().getSubject().getValue()).isEqualTo("cindy");
		assertThat(actor.getParent().getIssuer()).isNull();
		assertThat(actor.getParent().getParent()).isNull();

		// top-level JSON object
		JsonObjectBuilder topLevel = Json.createObjectBuilder();
		topLevel.add("act", actor.toJSONObject());

		actor = Actor.parseTopLevel(topLevel.build());
		assertThat(actor.getSubject().getValue()).isEqualTo("claire");
		assertThat(actor.getIssuer().getValue()).isEqualTo("https://openid.c2id.com");
		assertThat(actor.getParent().getSubject().getValue()).isEqualTo("cindy");
		assertThat(actor.getParent().getIssuer()).isNull();
		assertThat(actor.getParent().getParent()).isNull();
	}

	@Test
	public void testParseEmptyTopLevel()
		throws OAuth2JSONParseException {

		JsonObjectBuilder jsonObject = Json.createObjectBuilder();

		assertThat(Actor.parseTopLevel(jsonObject.build())).isNull();
	}

	@Test
	public void testToString() {
		
		Actor actor = new Actor(new Subject("claire"));
		
		assertThat(actor.toString()).isEqualTo("{\"sub\":\"claire\"}");
	}

	@Test
	public void testEquality() {

		assertThat(new Actor(new Subject("claire")).equals(new Actor(new Subject("claire")))).isTrue();

		assertThat(new Actor(new Subject("claire"), new Issuer("https://openid.com"), null)
			.equals(new Actor(new Subject("claire"), new Issuer("https://openid.com"), null))).isTrue();

		assertThat(new Actor(new Subject("claire"), new Issuer("https://openid.com"), new Actor(new Subject("cindy")))
			.equals(new Actor(new Subject("claire"), new Issuer("https://openid.com"), new Actor(new Subject("cindy"))))).isTrue();
	}
}
