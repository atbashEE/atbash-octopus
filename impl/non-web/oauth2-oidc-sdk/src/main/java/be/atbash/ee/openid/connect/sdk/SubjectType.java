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
import be.atbash.util.StringUtils;


/**
 * Enumeration of the subject identifier types.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 8.
 * </ul>
 */
public enum SubjectType {


    /**
     * Pairwise.
     */
    PAIRWISE,


    /**
     * Public.
     */
    PUBLIC;


    /**
     * Returns the string representation of this subject identifier
     * type.
     *
     * @return The string representation of this subject identifier
     * type.
     */
    public String toString() {

        return super.toString().toLowerCase();
    }


    /**
     * Parses a subject identifier type.
     *
     * @param s The string to parse.
     * @return The subject identifier type.
     * @throws OAuth2JSONParseException If the parsed string is {@code null} or
     *                                  doesn't match a subject identifier type.
     */
    public static SubjectType parse(String s)
            throws OAuth2JSONParseException {
        if (StringUtils.isEmpty(s)) {
            throw new OAuth2JSONParseException("Null or empty subject type string");
        }

        if ("pairwise".equals(s)) {

            return PAIRWISE;

        } else if ("public".equals(s)) {

            return PUBLIC;

        } else {

            throw new OAuth2JSONParseException("Unknown subject type: " + s);
        }
    }
}