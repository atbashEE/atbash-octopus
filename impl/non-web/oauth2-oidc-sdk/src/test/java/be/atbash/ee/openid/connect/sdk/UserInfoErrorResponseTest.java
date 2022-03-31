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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.token.BearerTokenError;
import org.junit.jupiter.api.Test;

import jakarta.json.JsonObject;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests the UserInfo error response class.
 */
public class UserInfoErrorResponseTest {

    @Test
    public void testStandardErrors() {

        assertThat(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_REQUEST)).isTrue();
        assertThat(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.MISSING_TOKEN)).isTrue();
        assertThat(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INVALID_TOKEN)).isTrue();
        assertThat(UserInfoErrorResponse.getStandardErrors().contains(BearerTokenError.INSUFFICIENT_SCOPE)).isTrue();
        assertThat(UserInfoErrorResponse.getStandardErrors()).hasSize(4);
    }

    @Test
    public void testConstructAndParse()
            throws Exception {

        UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN);

        assertThat(errorResponse.indicatesSuccess()).isFalse();

        HTTPResponse httpResponse = errorResponse.toHTTPResponse();

        assertThat(httpResponse.getStatusCode()).isEqualTo(401);

        assertThat(httpResponse.getWWWAuthenticate()).isEqualTo("Bearer error=\"invalid_token\", error_description=\"Invalid access token\"");

        errorResponse = UserInfoErrorResponse.parse(httpResponse);

        assertThat(errorResponse.indicatesSuccess()).isFalse();

        assertThat(errorResponse.getErrorObject()).isEqualTo(BearerTokenError.INVALID_TOKEN);
    }

    @Test
    public void testOtherError()
            throws Exception {

        ErrorObject error = new ErrorObject("conflict", "Couldn't encrypt UserInfo JWT: Missing / expired client_secret", 409);

        UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(error);

        assertThat(errorResponse.getErrorObject()).isEqualTo(error);

        HTTPResponse httpResponse = errorResponse.toHTTPResponse();
        assertThat(httpResponse.getStatusCode()).isEqualTo(409);
        assertThat(httpResponse.getContentType().toString()).isEqualTo("application/json; charset=UTF-8");
        assertThat(httpResponse.getWWWAuthenticate()).isNull();
        JsonObject jsonObject = httpResponse.getContentAsJSONObject();
        assertThat(jsonObject.getString("error")).isEqualTo(error.getCode());
        assertThat(jsonObject.getString("error_description")).isEqualTo(error.getDescription());
        assertThat(jsonObject).hasSize(2);

        errorResponse = UserInfoErrorResponse.parse(httpResponse);

        assertThat(errorResponse.getErrorObject().getCode()).isEqualTo(error.getCode());
        assertThat(errorResponse.getErrorObject().getDescription()).isEqualTo(error.getDescription());
        assertThat(errorResponse.getErrorObject().getURI()).isNull();
        assertThat(errorResponse.getErrorObject().getHTTPStatusCode()).isEqualTo(error.getHTTPStatusCode());
    }
}
