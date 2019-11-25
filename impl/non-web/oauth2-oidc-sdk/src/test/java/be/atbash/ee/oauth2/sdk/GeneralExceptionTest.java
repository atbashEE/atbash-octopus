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
package be.atbash.ee.oauth2.sdk;



import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.id.State;
import org.junit.Test;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the general exception class.
 */
public class GeneralExceptionTest {

	@Test
	public void testConstructor1() {

		GeneralException e = new GeneralException("message");
		assertThat(e.getMessage()).isEqualTo("message");

		assertThat(e.getErrorObject()).isNull();
		assertThat(e.getClientID()).isNull();
		assertThat(e.getRedirectionURI()).isNull();
		assertThat(e.getState()).isNull();
	}

	@Test
	public void testConstructor2() {

		GeneralException e = new GeneralException("message", new IllegalArgumentException());
		assertThat(e.getMessage()).isEqualTo("message");

		assertThat(e.getErrorObject()).isNull();
		assertThat(e.getClientID()).isNull();
		assertThat(e.getRedirectionURI()).isNull();
		assertThat(e.getState()).isNull();
	}

	@Test
	public void testConstructor3() {

		GeneralException e = new GeneralException("message", OAuth2Error.INVALID_REQUEST, new IllegalArgumentException());
		assertThat(e.getMessage()).isEqualTo("message");

		assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
		assertThat(e.getClientID()).isNull();
		assertThat(e.getRedirectionURI()).isNull();
		assertThat(e.getState()).isNull();
	}

	@Test
	public void testConstructor4()
		throws Exception {

		GeneralException e = new GeneralException(
			"message",
			OAuth2Error.INVALID_REQUEST,
			new ClientID("abc"),
			new URI("https://redirect.com"),
			ResponseMode.QUERY,
			new State("123"));

		assertThat(e.getMessage()).isEqualTo("message");
		assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
		assertThat(e.getClientID().getValue()).isEqualTo("abc");
		assertThat(e.getRedirectionURI().toString()).isEqualTo("https://redirect.com");
		assertThat(e.getResponseMode()).isEqualTo(ResponseMode.QUERY);
		assertThat(e.getState().getValue()).isEqualTo("123");
	}

	@Test
	public void testConstructor5()
		throws Exception {

		GeneralException e = new GeneralException(
			"message",
			OAuth2Error.INVALID_REQUEST,
			new ClientID("abc"),
			new URI("https://redirect.com"),
			ResponseMode.FRAGMENT,
			new State("123"),
			new IllegalArgumentException());

		assertThat(e.getMessage()).isEqualTo("message");
		assertThat(e.getErrorObject()).isEqualTo(OAuth2Error.INVALID_REQUEST);
		assertThat(e.getClientID().getValue()).isEqualTo("abc");
		assertThat(e.getRedirectionURI().toString()).isEqualTo("https://redirect.com");
		assertThat(e.getResponseMode()).isEqualTo(ResponseMode.FRAGMENT);
		assertThat(e.getState().getValue()).isEqualTo("123");
	}

	@Test
	public void testErrorObjectConstructor() {

		GeneralException e = new GeneralException(OAuth2Error.INVALID_GRANT.setDescription("Invalid code"));

		assertThat(e.getMessage()).isEqualTo("Invalid code");
		assertThat(e.getErrorObject().getCode()).isEqualTo(OAuth2Error.INVALID_GRANT.getCode());
		assertThat(e.getErrorObject().getDescription()).isEqualTo("Invalid code");
	}
}
