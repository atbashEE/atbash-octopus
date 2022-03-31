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


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.SerializeException;
import be.atbash.ee.oauth2.sdk.SuccessResponse;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.openid.connect.sdk.claims.UserInfo;
import be.atbash.ee.security.octopus.nimbus.jwt.JWT;

import jakarta.mail.internet.ContentType;


/**
 * UserInfo success response.
 *
 * <p>The UserInfo claims may be passed as an unprotected JSON object or as a
 * plain, signed or encrypted JSON Web Token (JWT). Use the appropriate
 * constructor for that.
 *
 * <p>Example UserInfo HTTP response:
 *
 * <pre>
 * HTTP/1.1 200 OK
 * Content-Type: application/json
 *
 * {
 *  "sub"         : "248289761001",
 *  "name"        : "Jane Doe"
 *  "given_name"  : "Jane",
 *  "family_name" : "Doe",
 *  "email"       : "janedoe@example.com",
 *  "picture"     : "http://example.com/janedoe/me.jpg"
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 5.3.2.
 * </ul>
 */
public class UserInfoSuccessResponse
        extends UserInfoResponse
        implements SuccessResponse {


    /**
     * The UserInfo claims set, serialisable to a JSON object.
     */
    private final UserInfo claimsSet;


    /**
     * The UserInfo claims set, as plain, signed or encrypted JWT.
     */
    private final JWT jwt;


    /**
     * Creates a new UserInfo success response where the claims are
     * specified as an unprotected UserInfo claims set.
     *
     * @param claimsSet The UserInfo claims set. Must not be {@code null}.
     */
    public UserInfoSuccessResponse(UserInfo claimsSet) {

        if (claimsSet == null) {
            throw new IllegalArgumentException("The claims must not be null");
        }

        this.claimsSet = claimsSet;

        this.jwt = null;
    }


    /**
     * Creates a new UserInfo success response where the claims are
     * specified as a plain, signed or encrypted JSON Web Token (JWT).
     *
     * @param jwt The UserInfo claims set. Must not be {@code null}.
     */
    public UserInfoSuccessResponse(JWT jwt) {

        if (jwt == null) {
            throw new IllegalArgumentException("The claims JWT must not be null");
        }

        this.jwt = jwt;

        this.claimsSet = null;
    }


    @Override
    public boolean indicatesSuccess() {

        return true;
    }


    /**
     * Gets the content type of this UserInfo response.
     *
     * @return The content type, according to the claims format.
     */
    public ContentType getContentType() {

        if (claimsSet != null) {
            return CommonContentTypes.APPLICATION_JSON;
        } else {
            return CommonContentTypes.APPLICATION_JWT;
        }
    }


    /**
     * Gets the UserInfo claims set as an unprotected UserInfo claims set.
     *
     * @return The UserInfo claims set, {@code null} if it was specified as
     * JSON Web Token (JWT) instead.
     */
    public UserInfo getUserInfo() {

        return claimsSet;
    }


    /**
     * Gets the UserInfo claims set as a plain, signed or encrypted JSON
     * Web Token (JWT).
     *
     * @return The UserInfo claims set as a JSON Web Token (JWT),
     * {@code null} if it was specified as an unprotected UserInfo
     * claims set instead.
     */
    public JWT getUserInfoJWT() {

        return jwt;
    }


    @Override
    public HTTPResponse toHTTPResponse() {

        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);

        httpResponse.setContentType(getContentType());

        String content;

        if (claimsSet != null) {

            content = claimsSet.toJSONObject().build().toString();

        } else {

            try {
                content = jwt.serialize();

            } catch (IllegalStateException e) {

                throw new SerializeException("Couldn't serialize UserInfo claims JWT: " +
                        e.getMessage(), e);
            }
        }

        httpResponse.setContent(content);

        return httpResponse;
    }


    /**
     * Parses a UserInfo response from the specified HTTP response.
     *
     * <p>Example HTTP response:
     *
     * <pre>
     * HTTP/1.1 200 OK
     * Content-Type: application/json
     *
     * {
     *  "sub"         : "248289761001",
     *  "name"        : "Jane Doe"
     *  "given_name"  : "Jane",
     *  "family_name" : "Doe",
     *  "email"       : "janedoe@example.com",
     *  "picture"     : "http://example.com/janedoe/me.jpg"
     * }
     * </pre>
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The UserInfo response.
     * @throws OAuth2JSONParseException If the HTTP response couldn't be parsed to a
     *                                  UserInfo response.
     */
    public static UserInfoSuccessResponse parse(HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        httpResponse.ensureStatusCode(HTTPResponse.SC_OK);

        httpResponse.ensureContentType();

        ContentType ct = httpResponse.getContentType();


        UserInfoSuccessResponse response;

        if (ct.match(CommonContentTypes.APPLICATION_JSON)) {

            UserInfo claimsSet;

            try {
                claimsSet = new UserInfo(httpResponse.getContentAsJSONObject());

            } catch (Exception e) {

                throw new OAuth2JSONParseException("Couldn't parse UserInfo claims: " +
                        e.getMessage(), e);
            }

            response = new UserInfoSuccessResponse(claimsSet);
        } else if (ct.match(CommonContentTypes.APPLICATION_JWT)) {

            JWT jwt;

            try {
                jwt = httpResponse.getContentAsJWT();

            } catch (OAuth2JSONParseException e) {

                throw new OAuth2JSONParseException("Couldn't parse UserInfo claims JWT: " +
                        e.getMessage(), e);
            }

            response = new UserInfoSuccessResponse(jwt);
        } else {
            throw new OAuth2JSONParseException("Unexpected Content-Type, must be " +
                    CommonContentTypes.APPLICATION_JSON +
                    " or " +
                    CommonContentTypes.APPLICATION_JWT);
        }

        return response;
    }
}
