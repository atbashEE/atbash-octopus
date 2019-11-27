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
package be.atbash.ee.openid.connect.sdk;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.Response;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;


/**
 * The base abstract class for UserInfo success and error responses.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 5.3.2 and 5.3.3.
 *     <li>OAuth 2.0 Bearer Token Usage (RFC 6750), section 3.1.
 * </ul>
 */
public abstract class UserInfoResponse implements Response {


    /**
     * Casts this response to a UserInfo success response.
     *
     * @return The UserInfo success response.
     */
    public UserInfoSuccessResponse toSuccessResponse() {
        return (UserInfoSuccessResponse) this;
    }


    /**
     * Casts this response to a UserInfo error response.
     *
     * @return The UserInfo error response.
     */
    public UserInfoErrorResponse toErrorResponse() {
        return (UserInfoErrorResponse) this;
    }


    /**
     * Parses a UserInfo response from the specified HTTP response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The UserInfo success or error response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  UserInfo response.
     */
    public static UserInfoResponse parse(HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        if (httpResponse.getStatusCode() == HTTPResponse.SC_OK) {
            return UserInfoSuccessResponse.parse(httpResponse);
        } else {
            return UserInfoErrorResponse.parse(httpResponse);
        }
    }
}