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
package be.atbash.ee.oauth2.sdk.util;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;

import jakarta.mail.internet.ContentType;


/**
 * Content type matching.
 */
public final class ContentTypeUtils {


    /**
     * Ensures the content type of an HTTP header matches an expected
     * value. Note that this method compares only the primary type and
     * subtype; any content type parameters, such as {@code charset}, are
     * ignored.
     *
     * @param expected The expected content type. Must not be {@code null}.
     * @param found    The found content type. May be {@code null}.
     * @throws OAuth2JSONParseException If the found content type is {@code null} or
     *                                  it primary and subtype and doesn't match the
     *                                  expected.
     */
    public static void ensureContentType(ContentType expected, ContentType found)
            throws OAuth2JSONParseException {

        if (found == null) {
            throw new OAuth2JSONParseException("Missing HTTP Content-Type header");
        }

        if (!expected.match(found)) {
            throw new OAuth2JSONParseException("The HTTP Content-Type header must be " + expected);
        }
    }


    /**
     * Prevents public instantiation.
     */
    private ContentTypeUtils() {
    }
}
