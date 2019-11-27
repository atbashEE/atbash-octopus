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
package be.atbash.ee.oauth2.sdk.client;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.JsonObject;
import java.net.URI;
import java.text.ParseException;
import java.util.Date;


/**
 * Client credentials parser.
 */
public class ClientCredentialsParser {


    /**
     * Parses a client identifier from the specified JSON object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @return The client identifier.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static ClientID parseID(JsonObject jsonObject)
            throws OAuth2JSONParseException {

        if (!jsonObject.containsKey("client_id")) {
            throw new OAuth2JSONParseException("Missing JSON object member with key \"client_id\"");
        }
        return new ClientID(jsonObject.getString("client_id"));
    }


    /**
     * Parses a client identifier issue date from the specified JSON
     * object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @return The client identifier issue date, {@code null} if not
     * specified.
     */
    public static Date parseIDIssueDate(JsonObject jsonObject) {

        if (jsonObject.containsKey("client_id_issued_at")) {

            return new Date(jsonObject.getJsonNumber("client_id_issued_at").longValue() * 1000);
        } else {
            return null;
        }
    }


    /**
     * Parses a client secret from the specified JSON object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @return The client secret, {@code null} if not specified.
     */
    public static Secret parseSecret(JsonObject jsonObject) {

        if (jsonObject.containsKey("client_secret")) {

            String value = jsonObject.getString("client_secret");

            Date exp = null;

            if (jsonObject.containsKey("client_secret_expires_at")) {

                long t = jsonObject.getJsonNumber("client_secret_expires_at").longValue();

                if (t > 0) {
                    exp = new Date(t * 1000);
                }
            }

            return new Secret(value, exp);
        } else {
            return null;
        }
    }


    /**
     * Parses a client registration URI from the specified JSON object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @return The client registration URI, {@code null} if not specified.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static URI parseRegistrationURI(JsonObject jsonObject)
            throws OAuth2JSONParseException {

        try {
            return JSONObjectUtils.getURI(jsonObject, "registration_client_uri");
        } catch (ParseException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
    }


    /**
     * Parses a client registration access token from the specified JSON
     * object.
     *
     * @param jsonObject The JSON object. Must not be {@code null}.
     * @return The client registration access token, {@code null} if not
     * specified.
     */
    public static BearerAccessToken parseRegistrationAccessToken(JsonObject jsonObject) {

        if (jsonObject.containsKey("registration_access_token")) {

            return new BearerAccessToken(jsonObject.getString("registration_access_token"));
        } else {
            return null;
        }
    }
}
