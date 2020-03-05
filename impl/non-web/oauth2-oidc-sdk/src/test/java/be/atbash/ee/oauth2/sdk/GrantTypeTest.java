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


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the grant type class.
 */
public class GrantTypeTest  {

	@Test
	public void testConstants() {

		assertThat(GrantType.AUTHORIZATION_CODE.toString()).isEqualTo("authorization_code");
		assertThat(GrantType.IMPLICIT.toString()).isEqualTo("implicit");
		assertThat(GrantType.REFRESH_TOKEN.toString()).isEqualTo("refresh_token");
		assertThat(GrantType.PASSWORD.toString()).isEqualTo("password");
		assertThat(GrantType.CLIENT_CREDENTIALS.toString()).isEqualTo("client_credentials");
		assertThat(GrantType.JWT_BEARER.toString()).isEqualTo("urn:ietf:params:oauth:grant-type:jwt-bearer");
		assertThat(GrantType.SAML2_BEARER.toString()).isEqualTo("urn:ietf:params:oauth:grant-type:saml2-bearer");
	}

	@Test
	public void testClientAuthRequirement() {

		assertThat(GrantType.AUTHORIZATION_CODE.requiresClientAuthentication()).isFalse();
		assertThat(GrantType.IMPLICIT.requiresClientAuthentication()).isFalse();
		assertThat(GrantType.REFRESH_TOKEN.requiresClientAuthentication()).isFalse();
		assertThat(GrantType.PASSWORD.requiresClientAuthentication()).isFalse();
		assertThat(GrantType.CLIENT_CREDENTIALS.requiresClientAuthentication()).isTrue();
		assertThat(GrantType.JWT_BEARER.requiresClientAuthentication()).isFalse();
		assertThat(GrantType.SAML2_BEARER.requiresClientAuthentication()).isFalse();
	}

	@Test
	public void testClientIDRequirement() {

		assertThat(GrantType.AUTHORIZATION_CODE.requiresClientID()).isTrue();
		assertThat(GrantType.IMPLICIT.requiresClientID()).isTrue();
		assertThat(GrantType.REFRESH_TOKEN.requiresClientID()).isFalse();
		assertThat(GrantType.PASSWORD.requiresClientID()).isFalse();
		assertThat(GrantType.CLIENT_CREDENTIALS.requiresClientID()).isTrue();
		assertThat(GrantType.JWT_BEARER.requiresClientID()).isFalse();
		assertThat(GrantType.SAML2_BEARER.requiresClientID()).isFalse();
	}

	@Test
	public void testRequestParameters() {

		assertThat(GrantType.AUTHORIZATION_CODE.getRequestParameterNames()).contains("code");
		assertThat(GrantType.AUTHORIZATION_CODE.getRequestParameterNames()).contains("redirect_uri");
		assertThat(GrantType.AUTHORIZATION_CODE.getRequestParameterNames()).contains("code_verifier");
		assertThat(GrantType.AUTHORIZATION_CODE.getRequestParameterNames()).hasSize(3);

		assertThat(GrantType.IMPLICIT.getRequestParameterNames().isEmpty()).isTrue();

		assertThat(GrantType.PASSWORD.getRequestParameterNames()).contains("username");
		assertThat(GrantType.PASSWORD.getRequestParameterNames()).contains("password");
		assertThat(GrantType.PASSWORD.getRequestParameterNames()).hasSize(2);

		assertThat(GrantType.CLIENT_CREDENTIALS.getRequestParameterNames().isEmpty()).isTrue();

		assertThat(GrantType.JWT_BEARER.getRequestParameterNames()).contains("assertion");
		assertThat(GrantType.JWT_BEARER.getRequestParameterNames()).hasSize(1);

		assertThat(GrantType.SAML2_BEARER.getRequestParameterNames()).contains("assertion");
		assertThat(GrantType.SAML2_BEARER.getRequestParameterNames()).hasSize(1);
	}

	@Test
	public void testDefaultConstructor() {

		GrantType grantType = new GrantType("custom");
		assertThat(grantType.getValue()).isEqualTo("custom");
		assertThat(grantType.requiresClientAuthentication()).isFalse();
		assertThat(grantType.requiresClientID()).isFalse();
	}

	@Test
	public void testParseStandard()
		throws OAuth2JSONParseException {

		assertThat(GrantType.parse(GrantType.AUTHORIZATION_CODE.getValue())).isEqualTo(GrantType.AUTHORIZATION_CODE);
		assertThat(GrantType.parse(GrantType.IMPLICIT.getValue())).isEqualTo(GrantType.IMPLICIT);
		assertThat(GrantType.parse(GrantType.REFRESH_TOKEN.getValue())).isEqualTo(GrantType.REFRESH_TOKEN);
		assertThat(GrantType.parse(GrantType.PASSWORD.getValue())).isEqualTo(GrantType.PASSWORD);
		assertThat(GrantType.parse(GrantType.CLIENT_CREDENTIALS.getValue())).isEqualTo(GrantType.CLIENT_CREDENTIALS);
		assertThat(GrantType.parse(GrantType.JWT_BEARER.getValue())).isEqualTo(GrantType.JWT_BEARER);
		assertThat(GrantType.parse(GrantType.SAML2_BEARER.getValue())).isEqualTo(GrantType.SAML2_BEARER);
	}

	@Test
	public void testParseCustomGrant()
		throws OAuth2JSONParseException {

		GrantType grantType = GrantType.parse("custom");

		assertThat(grantType.getValue()).isEqualTo("custom");
		assertThat(grantType.requiresClientAuthentication()).isFalse();
		assertThat(grantType.requiresClientID()).isFalse();
		assertThat(grantType.getRequestParameterNames().isEmpty()).isTrue();
	}

	@Test
	public void testParseNull() {

        Assertions.assertThrows(OAuth2JSONParseException.class, () -> GrantType.parse(null));

    }

	@Test
	public void testParseEmpty() {

        Assertions.assertThrows(OAuth2JSONParseException.class, () -> GrantType.parse(""));

    }

	@Test
	public void testParseBlank() {

        Assertions.assertThrows(OAuth2JSONParseException.class, () -> GrantType.parse(" "));

    }
}
