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
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Error object, used to encapsulate OAuth 2.0 and other errors.
 *
 * <p>Example error object as HTTP response:
 *
 * <pre>
 * HTTP/1.1 400 Bad Request
 * Content-Type: application/json;charset=UTF-8
 * Cache-Control: no-store
 * Pragma: no-cache
 *
 * {
 *   "error" : "invalid_request"
 * }
 * </pre>
 */
public class ErrorObject {


    /**
     * The error code, may not always be defined.
     */
    private final String code;


    /**
     * Optional error description.
     */
    private final String description;


    /**
     * Optional HTTP status code, 0 if not specified.
     */
    private final int httpStatusCode;


    /**
     * Optional URI of a web page that includes additional information
     * about the error.
     */
    private final URI uri;


    /**
     * Creates a new error with the specified code.
     *
     * @param code The error code, {@code null} if not specified.
     */
    public ErrorObject(String code) {

        this(code, null, 0, null);
    }


    /**
     * Creates a new error with the specified code and description.
     *
     * @param code        The error code, {@code null} if not specified.
     * @param description The error description, {@code null} if not
     *                    specified.
     */
    public ErrorObject(String code, String description) {

        this(code, description, 0, null);
    }


    /**
     * Creates a new error with the specified code, description and HTTP
     * status code.
     *
     * @param code           The error code, {@code null} if not specified.
     * @param description    The error description, {@code null} if not
     *                       specified.
     * @param httpStatusCode The HTTP status code, zero if not specified.
     */
    public ErrorObject(String code, String description,
                       int httpStatusCode) {

        this(code, description, httpStatusCode, null);
    }


    /**
     * Creates a new error with the specified code, description, HTTP
     * status code and page URI.
     *
     * @param code           The error code, {@code null} if not specified.
     * @param description    The error description, {@code null} if not
     *                       specified.
     * @param httpStatusCode The HTTP status code, zero if not specified.
     * @param uri            The error page URI, {@code null} if not
     *                       specified.
     */
    public ErrorObject(String code, String description,
                       int httpStatusCode, URI uri) {

        this.code = code;
        this.description = description;
        this.httpStatusCode = httpStatusCode;
        this.uri = uri;
    }


    /**
     * Gets the error code.
     *
     * @return The error code, {@code null} if not specified.
     */
    public String getCode() {

        return code;
    }


    /**
     * Gets the error description.
     *
     * @return The error description, {@code null} if not specified.
     */
    public String getDescription() {

        return description;
    }


    /**
     * Sets the error description.
     *
     * @param description The error description, {@code null} if not
     *                    specified.
     * @return A copy of this error with the specified description.
     */
    public ErrorObject setDescription(String description) {

        return new ErrorObject(getCode(), description, getHTTPStatusCode(), getURI());
    }


    /**
     * Appends the specified text to the error description.
     *
     * @param text The text to append to the error description,
     *             {@code null} if not specified.
     * @return A copy of this error with the specified appended
     * description.
     */
    public ErrorObject appendDescription(String text) {

        String newDescription;

        if (getDescription() != null) {
            newDescription = getDescription() + text;
        } else {
            newDescription = text;
        }

        return new ErrorObject(getCode(), newDescription, getHTTPStatusCode(), getURI());
    }


    /**
     * Gets the HTTP status code.
     *
     * @return The HTTP status code, zero if not specified.
     */
    public int getHTTPStatusCode() {

        return httpStatusCode;
    }


    /**
     * Sets the HTTP status code.
     *
     * @param httpStatusCode The HTTP status code, zero if not specified.
     * @return A copy of this error with the specified HTTP status code.
     */
    public ErrorObject setHTTPStatusCode(int httpStatusCode) {

        return new ErrorObject(getCode(), getDescription(), httpStatusCode, getURI());
    }


    /**
     * Gets the error page URI.
     *
     * @return The error page URI, {@code null} if not specified.
     */
    public URI getURI() {

        return uri;
    }


    /**
     * Sets the error page URI.
     *
     * @param uri The error page URI, {@code null} if not specified.
     * @return A copy of this error with the specified page URI.
     */
    public ErrorObject setURI(URI uri) {

        return new ErrorObject(getCode(), getDescription(), getHTTPStatusCode(), uri);
    }


    /**
     * Returns a JSON object representation of this error object.
     *
     * <p>Example:
     *
     * <pre>
     * {
     *   "error"             : "invalid_grant",
     *   "error_description" : "Invalid resource owner credentials"
     * }
     * </pre>
     *
     * @return The JSON object.
     */
    public JsonObject toJSONObject() {

        JsonObjectBuilder result = Json.createObjectBuilder();

        if (code != null) {
            result.add("error", code);
        }

        if (description != null) {
            result.add("error_description", description);
        }

        if (uri != null) {
            result.add("error_uri", uri.toString());
        }

        return result.build();
    }


    /**
     * Returns a parameters representation of this error object. Suitable
     * for URL-encoded error responses.
     *
     * @return The parameters.
     */
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = new HashMap<>();

        if (getCode() != null) {
            params.put("error", Collections.singletonList(getCode()));
        }

        if (getDescription() != null) {
            params.put("error_description", Collections.singletonList(getDescription()));
        }

        if (getURI() != null) {
            params.put("error_uri", Collections.singletonList(getURI().toString()));
        }

        return params;
    }


    /**
     * @see #getCode
     */
    @Override
    public String toString() {

        return code != null ? code : "null";
    }


    @Override
    public int hashCode() {

        return code != null ? code.hashCode() : "null".hashCode();
    }


    @Override
    public boolean equals(Object object) {

        return object instanceof ErrorObject &&
                this.toString().equals(object.toString());
    }


    /**
     * Parses an error object from the specified JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The error object.
     */
    public static ErrorObject parse(JsonObject jsonObject) {

        String code = jsonObject.getString("error");

        String description = jsonObject.getString("error_description", null);


        URI uri = null;
        try {
            uri = JSONObjectUtils.getURI(jsonObject, "error_uri");
        } catch (java.text.ParseException e) {
            // ignore and continue
        }

        return new ErrorObject(code, description, 0, uri);
    }


    /**
     * Parses an error object from the specified parameters representation.
     * Suitable for URL-encoded error responses.
     *
     * @param params The parameters. Must not be {@code null}.
     * @return The error object.
     */
    public static ErrorObject parse(Map<String, List<String>> params) {

        String code = MultivaluedMapUtils.getFirstValue(params, "error");
        String description = MultivaluedMapUtils.getFirstValue(params, "error_description");
        String uriString = MultivaluedMapUtils.getFirstValue(params, "error_uri");

        URI uri = null;
        if (uriString != null) {
            try {
                uri = new URI(uriString);
            } catch (URISyntaxException e) {
                // ignore
            }
        }

        return new ErrorObject(code, description, 0, uri);
    }


    /**
     * Parses an error object from the specified HTTP response.
     *
     * @param httpResponse The HTTP response to parse. Must not be
     *                     {@code null}.
     * @return The error object.
     */
    public static ErrorObject parse(HTTPResponse httpResponse) {

        JsonObject jsonObject;
        try {
            jsonObject = httpResponse.getContentAsJSONObject();
        } catch (OAuth2JSONParseException e) {
            return new ErrorObject(null, null, httpResponse.getStatusCode());
        }

        ErrorObject intermediary = parse(jsonObject);

        return new ErrorObject(
                intermediary.getCode(),
                intermediary.description,
                httpResponse.getStatusCode(),
                intermediary.getURI());
    }
}
