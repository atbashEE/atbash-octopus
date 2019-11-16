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


import be.atbash.ee.oauth2.sdk.ResponseType;

/**
 * OpenID Connect {@link #ID_TOKEN id_token} response type value constant.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, sections 2 and 3.1.2.1.
 *     <li>OAuth 2.0 Multiple Response Type Encoding Practices.
 *     <li>OAuth 2.0 (RFC 6749), sections 3.1.1 and 4.1.1.
 * </ul>
 */
public class OIDCResponseTypeValue {


    /**
     * ID Token response type.
     */
    public static final ResponseType.Value ID_TOKEN = new ResponseType.Value("id_token");


    /**
     * None response type, should not be combined with other response type
     * values.
     */
    public static final ResponseType.Value NONE = new ResponseType.Value("none");


    /**
     * Prevents public instantiation.
     */
    private OIDCResponseTypeValue() {
    }
}
