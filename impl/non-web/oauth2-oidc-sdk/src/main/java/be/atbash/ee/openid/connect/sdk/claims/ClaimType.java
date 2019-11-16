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
package be.atbash.ee.openid.connect.sdk.claims;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;


/**
 * Enumeration of the claim types.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Core 1.0, section 5.6.
 *     <li>OpenID Connect Discovery 1.0, section 3.
 * </ul>
 */
public enum ClaimType {

    /**
     * Claims that are directly asserted by the OpenID Connect provider.
     */
    NORMAL,


    /**
     * Claims that are asserted by a claims provider other than the
     * OpenID Connect Provider but are returned by OpenID Connect provider.
     */
    AGGREGATED,


    /**
     * Claims that are asserted by a claims provider other than the OpenID
     * Connect provider but are returned as references by the OpenID
     * Connect provider.
     */
    DISTRIBUTED;


    /**
     * Returns the string identifier of this claim type.
     *
     * @return The string identifier.
     */
    @Override
    public String toString() {

        return super.toString().toLowerCase();
    }


    /**
     * Parses a claim type.
     *
     * @param s The string to parse. Must not be {@code null}.
     * @return The claim type.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static ClaimType parse(final String s)
            throws OAuth2JSONParseException {

        if (s.equals("normal")) {
            return NORMAL;
        }

        if (s.equals("aggregated")) {
            return AGGREGATED;
        }

        if (s.equals("distributed")) {
            return DISTRIBUTED;
        }

        throw new OAuth2JSONParseException("Unknow claim type: " + s);
    }
}
