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


import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.oauth2.sdk.token.BearerTokenError;
import be.atbash.ee.oauth2.sdk.token.RefreshToken;
import be.atbash.ee.oauth2.sdk.token.Tokens;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenResponseTest{
	
	@Test
	public void testToSuccessResponse()
		throws Exception {
		
		Tokens tokens = new Tokens(new BearerAccessToken(), new RefreshToken());
		AccessTokenResponse accessTokenResponse = new AccessTokenResponse(tokens);
		
		HTTPResponse httpResponse = accessTokenResponse.toHTTPResponse();
		
		accessTokenResponse = TokenResponse.parse(httpResponse).toSuccessResponse();
		
		assertThat(accessTokenResponse.getTokens().getAccessToken()).isEqualTo(tokens.getAccessToken());
		assertThat(accessTokenResponse.getTokens().getRefreshToken()).isEqualTo(tokens.getRefreshToken());
	}

	@Test
	public void testToErrorResponse()
		throws Exception {
		
		TokenErrorResponse tokenErrorResponse = new TokenErrorResponse(BearerTokenError.INVALID_TOKEN);
		
		HTTPResponse httpResponse = tokenErrorResponse.toHTTPResponse();
		
		tokenErrorResponse = TokenResponse.parse(httpResponse).toErrorResponse();
		
		assertThat(tokenErrorResponse.getErrorObject()).isEqualTo(BearerTokenError.INVALID_TOKEN);
	}
}
