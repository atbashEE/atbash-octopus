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
package be.atbash.ee.oauth2.sdk;


import be.atbash.ee.openid.connect.sdk.OIDCResponseTypeValue;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the response type class.
 */
public class ResponseTypeTest{
	
	@Test
	public void testConstants() {

		assertThat(ResponseType.Value.CODE.toString()).isEqualTo("code");
		assertThat(ResponseType.Value.TOKEN.toString()).isEqualTo("token");
	}

	@Test
	public void testVarargConstructor() {

		ResponseType rt = new ResponseType(ResponseType.Value.CODE, OIDCResponseTypeValue.ID_TOKEN);

		assertThat(rt).contains(ResponseType.Value.CODE);
		assertThat(rt).contains(OIDCResponseTypeValue.ID_TOKEN);
		assertThat(rt).hasSize(2);

		assertThat(rt.contains(ResponseType.Value.TOKEN)).isFalse();
		assertThat(rt.contains("token")).isFalse();
	}

	@Test
	public void testStringVarargConstructor() {

		ResponseType rt = new ResponseType("code", "id_token");

		assertThat(rt).contains(ResponseType.Value.CODE);
		assertThat(rt).contains(OIDCResponseTypeValue.ID_TOKEN);
		assertThat(rt).hasSize(2);
	}

	@Test
	public void testStringVarargConstructorNull() {

        Assertions.assertThrows(IllegalArgumentException.class, () -> new ResponseType((String) null));

    }

	@Test
	public void testCodeFlowDetection() {

		assertThat(new ResponseType("code").impliesCodeFlow()).isTrue();
		assertThat(new ResponseType("token").impliesCodeFlow()).isFalse();
		assertThat(new ResponseType("code", "token").impliesCodeFlow()).isFalse();
		assertThat(new ResponseType("code", "id_token", "token").impliesCodeFlow()).isFalse();
		assertThat(new ResponseType("token", "id_token").impliesCodeFlow()).isFalse();
		assertThat(new ResponseType("code", "id_token").impliesCodeFlow()).isFalse();
		assertThat(new ResponseType("id_token").impliesCodeFlow()).isFalse();
	}

	@Test
	public void testImplicitFlowDetection() {
		
		assertThat(new ResponseType("code").impliesImplicitFlow()).isFalse();
		assertThat(new ResponseType("token").impliesImplicitFlow()).isTrue();
		assertThat(new ResponseType("code", "token").impliesImplicitFlow()).isFalse();
		assertThat(new ResponseType("code", "id_token", "token").impliesImplicitFlow()).isFalse();
		assertThat(new ResponseType("token", "id_token").impliesImplicitFlow()).isTrue();
		assertThat(new ResponseType("code", "id_token").impliesImplicitFlow()).isFalse();
		assertThat(new ResponseType("id_token").impliesImplicitFlow()).isTrue();
	}

	@Test
	public void testHybridFlowDetection() {
		
		assertThat(new ResponseType("code").impliesHybridFlow()).isFalse();
		assertThat(new ResponseType("token").impliesHybridFlow()).isFalse();
		assertThat(new ResponseType("code", "token").impliesHybridFlow()).isTrue();
		assertThat(new ResponseType("code", "id_token", "token").impliesHybridFlow()).isTrue();
		assertThat(new ResponseType("token", "id_token").impliesHybridFlow()).isFalse();
		assertThat(new ResponseType("code", "id_token").impliesHybridFlow()).isTrue();
		assertThat(new ResponseType("id_token").impliesHybridFlow()).isFalse();
	}

    @Test
    public void testSerializeAndParse() throws OAuth2JSONParseException {

        ResponseType rt = new ResponseType();
        rt.add(ResponseType.Value.CODE);
        rt.add(new ResponseType.Value("id_token"));

        rt = ResponseType.parse(rt.toString());

        assertThat(rt).contains(ResponseType.Value.CODE);
        assertThat(rt).contains(new ResponseType.Value("id_token"));
        assertThat(rt).hasSize(2);
    }

	@Test
	public void testParseNull() {

        Assertions.assertThrows(OAuth2JSONParseException.class, () -> ResponseType.parse(null));

    }

	@Test
	public void testParseEmptyString() {

        Assertions.assertThrows(OAuth2JSONParseException.class, () -> ResponseType.parse(" "));
    }

	@Test
	public void testContains() {

		List<ResponseType> rtList = new ArrayList<>();

		ResponseType rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		rtList.add(rt1);

		ResponseType rt2 = new ResponseType();
		rt2.add(ResponseType.Value.TOKEN);
		rt2.add(OIDCResponseTypeValue.ID_TOKEN);
		rtList.add(rt2);

		assertThat(rtList).hasSize(2);

		rt1 = new ResponseType();
		rt1.add(ResponseType.Value.CODE);
		rtList.add(rt1);
		assertThat(rtList).contains(rt1);

		rt2 = new ResponseType();
		rt2.add(ResponseType.Value.TOKEN);
		rt2.add(OIDCResponseTypeValue.ID_TOKEN);
		rtList.add(rt2);
		assertThat(rtList).contains(rt2);

		ResponseType rt3 = new ResponseType();
		rt3.add(OIDCResponseTypeValue.ID_TOKEN);

		assertThat(rtList.contains(rt3)).isFalse();
	}

	@Test
	public void testValueComparison() {

		assertThat(new ResponseType.Value("code")).isEqualTo(ResponseType.Value.CODE);
	}

	@Test
	public void testMultipleEquality()
		throws Exception {

		assertThat(ResponseType.parse("code id_token").equals(ResponseType.parse("id_token code"))).isTrue();
	}
}
