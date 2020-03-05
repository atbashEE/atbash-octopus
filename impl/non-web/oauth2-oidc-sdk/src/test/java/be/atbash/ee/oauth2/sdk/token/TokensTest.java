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
package be.atbash.ee.oauth2.sdk.token;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.Scope;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.json.JsonObject;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the token pair class.
 */
public class TokensTest {

	@Test
	public void testAllDefined()
		throws OAuth2JSONParseException {

		AccessToken accessToken = new BearerAccessToken(60L, Scope.parse("openid email"));
		RefreshToken refreshToken = new RefreshToken();

		Tokens tokens = new Tokens(accessToken, refreshToken);

		assertThat(tokens.getAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getRefreshToken()).isEqualTo(refreshToken);

		assertThat(tokens.getParameterNames()).contains("token_type");
		assertThat(tokens.getParameterNames()).contains("access_token");
		assertThat(tokens.getParameterNames()).contains("expires_in");
		assertThat(tokens.getParameterNames()).contains("scope");
		assertThat(tokens.getParameterNames()).contains("refresh_token");
		assertThat(tokens.getParameterNames()).hasSize(5);

		JsonObject jsonObject = tokens.toJSONObject().build();
		assertThat(jsonObject.getString("token_type")).isEqualTo("Bearer");
		assertThat(jsonObject.getString("access_token")).isEqualTo(accessToken.getValue());
		assertThat(jsonObject.getJsonNumber("expires_in").longValue()).isEqualTo(60L);
		assertThat(jsonObject.getString("scope")).isEqualTo("openid email");
		assertThat(jsonObject.getString("refresh_token")).isEqualTo(refreshToken.getValue());
		assertThat(jsonObject).hasSize(5);

		tokens = Tokens.parse(jsonObject);

		assertThat(tokens.getAccessToken().getValue()).isEqualTo(accessToken.getValue());
		assertThat(tokens.getAccessToken().getLifetime()).isEqualTo(accessToken.getLifetime());
		assertThat(tokens.getAccessToken().getScope()).isEqualTo(accessToken.getScope());
		assertThat(tokens.getRefreshToken().getValue()).isEqualTo(refreshToken.getValue());
	}

	@Test
	public void testMinimalAccessTokenOnly()
		throws OAuth2JSONParseException {

		AccessToken accessToken = new BearerAccessToken();

		Tokens tokens = new Tokens(accessToken, null);

		assertThat(tokens.getAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getBearerAccessToken()).isEqualTo(accessToken);
		assertThat(tokens.getRefreshToken()).isNull();

		assertThat(tokens.getParameterNames()).contains("token_type");
		assertThat(tokens.getParameterNames()).contains("access_token");
		assertThat(tokens.getParameterNames()).hasSize(2);

		JsonObject jsonObject = tokens.toJSONObject().build();
		assertThat(jsonObject.getString("token_type")).isEqualTo("Bearer");
		assertThat(jsonObject.getString("access_token")).isEqualTo(accessToken.getValue());
		assertThat(jsonObject).hasSize(2);

		tokens = Tokens.parse(jsonObject);

		assertThat(tokens.getAccessToken().getValue()).isEqualTo(accessToken.getValue());
		assertThat(tokens.getAccessToken().getLifetime()).isEqualTo(accessToken.getLifetime());
		assertThat(tokens.getAccessToken().getScope()).isEqualTo(accessToken.getScope());
		assertThat(tokens.getRefreshToken()).isNull();
	}

	@Test
	public void testMissingAccessTokenException() {

        IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> new Tokens(null, null));
        assertThat(exception.getMessage()).isEqualTo("The access token must not be null");
    }
}