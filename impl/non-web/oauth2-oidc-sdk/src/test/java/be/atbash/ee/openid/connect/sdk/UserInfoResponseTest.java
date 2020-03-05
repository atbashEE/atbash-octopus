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


import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.Subject;
import be.atbash.ee.oauth2.sdk.token.BearerTokenError;
import be.atbash.ee.openid.connect.sdk.claims.UserInfo;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * UserInfo response test.
 */
public class UserInfoResponseTest {

    @Test
    public void testParseSuccess()
            throws Exception {

        UserInfoSuccessResponse successResponse = new UserInfoSuccessResponse(new UserInfo(new Subject("alice")));

        HTTPResponse httpResponse = successResponse.toHTTPResponse();

        UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

        assertThat(userInfoResponse.indicatesSuccess()).isTrue();

        successResponse = userInfoResponse.toSuccessResponse();

        assertThat(successResponse.getUserInfo().getSubject()).isEqualTo(new Subject("alice"));
    }

    @Test
    public void testParseBearerTokenError()
            throws Exception {

        UserInfoErrorResponse errorResponse = new UserInfoErrorResponse(BearerTokenError.INVALID_TOKEN);

        HTTPResponse httpResponse = errorResponse.toHTTPResponse();

        UserInfoResponse userInfoResponse = UserInfoResponse.parse(httpResponse);

        assertThat(userInfoResponse.indicatesSuccess()).isFalse();

        errorResponse = userInfoResponse.toErrorResponse();

        assertThat(errorResponse.getErrorObject()).isEqualTo(BearerTokenError.INVALID_TOKEN);
    }
}
