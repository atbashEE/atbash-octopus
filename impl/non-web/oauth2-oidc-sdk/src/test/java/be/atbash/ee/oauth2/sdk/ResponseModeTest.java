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


import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the response mode class.
 */
public class ResponseModeTest  {

	@Test
	public void testConstants() {

		assertThat(ResponseMode.QUERY.getValue()).isEqualTo("query");
		assertThat(ResponseMode.FRAGMENT.getValue()).isEqualTo("fragment");
		assertThat(ResponseMode.FORM_POST.getValue()).isEqualTo("form_post");
		assertThat(ResponseMode.QUERY_JWT.getValue()).isEqualTo("query.jwt");
		assertThat(ResponseMode.FRAGMENT_JWT.getValue()).isEqualTo("fragment.jwt");
		assertThat(ResponseMode.FORM_POST_JWT.getValue()).isEqualTo("form_post.jwt");
		assertThat(ResponseMode.JWT.getValue()).isEqualTo("jwt");
	}

	@Test
	public void testConstructor() {

		ResponseMode mode = new ResponseMode("query");
		assertThat(mode.getValue()).isEqualTo("query");
	}

	@Test
	public void testEquality() {
		
		assertThat(new ResponseMode("query")).isEqualTo(new ResponseMode("query"));
	}

	@Test
	public void testInequality() {

        assertThat(new ResponseMode("fragment")).isNotEqualTo(new ResponseMode("query"));
    }

	@Test
	public void testResolve_explicit() {
		
		assertThat(ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("code"))).isEqualTo(ResponseMode.QUERY);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("code", "token"))).isEqualTo(ResponseMode.QUERY);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("code", "token", "id_token"))).isEqualTo(ResponseMode.QUERY);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("code", "id_token"))).isEqualTo(ResponseMode.QUERY);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("token", "id_token"))).isEqualTo(ResponseMode.QUERY);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("id_token"))).isEqualTo(ResponseMode.QUERY);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY, new ResponseType("token"))).isEqualTo(ResponseMode.QUERY);
		
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("code"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("code", "token"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("code", "token", "id_token"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("code", "id_token"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("token", "id_token"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("id_token"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT, new ResponseType("token"))).isEqualTo(ResponseMode.FRAGMENT);
		
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("code"))).isEqualTo(ResponseMode.FORM_POST);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("code", "token"))).isEqualTo(ResponseMode.FORM_POST);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("code", "token", "id_token"))).isEqualTo(ResponseMode.FORM_POST);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("code", "id_token"))).isEqualTo(ResponseMode.FORM_POST);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("token", "id_token"))).isEqualTo(ResponseMode.FORM_POST);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("id_token"))).isEqualTo(ResponseMode.FORM_POST);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST, new ResponseType("token"))).isEqualTo(ResponseMode.FORM_POST);
		
		assertThat(ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("code"))).isEqualTo(ResponseMode.QUERY_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("code", "token"))).isEqualTo(ResponseMode.QUERY_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("code", "token", "id_token"))).isEqualTo(ResponseMode.QUERY_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("code", "id_token"))).isEqualTo(ResponseMode.QUERY_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("token", "id_token"))).isEqualTo(ResponseMode.QUERY_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("id_token"))).isEqualTo(ResponseMode.QUERY_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.QUERY_JWT, new ResponseType("token"))).isEqualTo(ResponseMode.QUERY_JWT);
		
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("code"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("code", "token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("code", "token", "id_token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("code", "id_token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("token", "id_token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("id_token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FRAGMENT_JWT, new ResponseType("token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("code"))).isEqualTo(ResponseMode.FORM_POST_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("code", "token"))).isEqualTo(ResponseMode.FORM_POST_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("code", "token", "id_token"))).isEqualTo(ResponseMode.FORM_POST_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("code", "id_token"))).isEqualTo(ResponseMode.FORM_POST_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("token", "id_token"))).isEqualTo(ResponseMode.FORM_POST_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("id_token"))).isEqualTo(ResponseMode.FORM_POST_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.FORM_POST_JWT, new ResponseType("token"))).isEqualTo(ResponseMode.FORM_POST_JWT);
	}

	@Test
	public void testResolve_fromBaseJWTMode() {
		
		assertThat(ResponseMode.resolve(ResponseMode.JWT, new ResponseType("code"))).isEqualTo(ResponseMode.QUERY_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.JWT, new ResponseType("code", "token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.JWT, new ResponseType("code", "token", "id_token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.JWT, new ResponseType("code", "id_token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.JWT, new ResponseType("token", "id_token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.JWT, new ResponseType("id_token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.JWT, new ResponseType("token"))).isEqualTo(ResponseMode.FRAGMENT_JWT);
		assertThat(ResponseMode.resolve(ResponseMode.JWT, null)).isEqualTo(ResponseMode.QUERY_JWT);
	}

	@Test
	public void testResolve_fromResponseType() {
		
		assertThat(ResponseMode.resolve(null, new ResponseType("code"))).isEqualTo(ResponseMode.QUERY);
		assertThat(ResponseMode.resolve(null, new ResponseType("code", "token"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(null, new ResponseType("code", "token", "id_token"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(null, new ResponseType("code", "id_token"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(null, new ResponseType("token", "id_token"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(null, new ResponseType("id_token"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(null, new ResponseType("token"))).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(ResponseMode.resolve(null, null)).isEqualTo(ResponseMode.QUERY);
	}
}
