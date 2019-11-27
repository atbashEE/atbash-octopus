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
package be.atbash.ee.oauth2.sdk.util;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.id.Identifier;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonReader;
import javax.json.stream.JsonParsingException;
import java.io.StringReader;
import java.net.URI;
import java.util.Collection;
import java.util.List;


/**
 * JSON array helper methods for parsing and typed retrieval of values.
 */
public final class JSONArrayUtils {


    /**
     * Parses a JSON array.
     *
     * <p>Specific JSON to Java entity mapping (as per JSON Simple):
     *
     * <ul>
     *     <li>JSON numbers mapped to {@code java.lang.Number}.
     *     <li>JSON integer numbers mapped to {@code long}.
     *     <li>JSON fraction numbers mapped to {@code double}.
     * </ul>
     *
     * @param data The JSON array string to parse. Must not be {@code null}.
     * @return The JSON array.
     * @throws OAuth2JSONParseException If the string cannot be parsed to a JSON
     *                                  array.
     */
    public static JsonArray parse(String data)
            throws OAuth2JSONParseException {

        JsonReader jsonReader = Json.createReader(new StringReader(data));

        try {
            return jsonReader.readArray();
        } catch (JsonParsingException e) {

            throw new OAuth2JSONParseException("The JSON entity is not an array");
        }
    }

    public static JsonArray asJsonArray(List<? extends Identifier> identifiers) {
        JsonArrayBuilder result = Json.createArrayBuilder();
        identifiers.forEach(id -> result.add(id.getValue()));
        return result.build();
    }

    public static JsonArray URIsasJsonArray(Collection<URI> uris) {
        JsonArrayBuilder result = Json.createArrayBuilder();
        uris.forEach(uri -> result.add(uri.toString()));
        return result.build();
    }

    /**
     * Prevents public instantiation.
     */
    private JSONArrayUtils() {
    }
}
