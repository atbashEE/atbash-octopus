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
package be.atbash.ee.oauth2.sdk.auth;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.SerializeException;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;
import be.atbash.ee.oauth2.sdk.util.URLUtils;

import jakarta.mail.internet.ContentType;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


/**
 * Client secret post authentication at the Token endpoint. Implements
 * {@link ClientAuthenticationMethod#CLIENT_SECRET_POST}.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), sections 2.3.1 and 3.2.1.
 *     <li>OpenID Connect Core 1.0, section 9.
 * </ul>
 */
public final class ClientSecretPost extends PlainClientSecret {


    /**
     * Creates a new client secret post authentication.
     *
     * @param clientID The client identifier. Must not be {@code null}.
     * @param secret   The client secret. Must not be {@code null}.
     */
    public ClientSecretPost(ClientID clientID, Secret secret) {

        super(ClientAuthenticationMethod.CLIENT_SECRET_POST, clientID, secret);
    }


    /**
     * Returns the parameter representation of this client secret post
     * authentication. Note that the parameters are not
     * {@code application/x-www-form-urlencoded} encoded.
     *
     * <p>Parameters map:
     *
     * <pre>
     * "client_id" = [client-identifier]
     * "client_secret" = [client-secret]
     * </pre>
     *
     * @return The parameters map, with keys "client_id" and
     * "client_secret".
     */
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = new HashMap<>();
        params.put("client_id", Collections.singletonList(getClientID().getValue()));
        params.put("client_secret", Collections.singletonList(getClientSecret().getValue()));
        return params;
    }


    @Override
    public void applyTo(HTTPRequest httpRequest) {

        if (httpRequest.getMethod() != HTTPRequest.Method.POST) {
            throw new SerializeException("The HTTP request method must be POST");
        }

        ContentType ct = httpRequest.getContentType();

        if (ct == null) {
            throw new SerializeException("Missing HTTP Content-Type header");
        }

        if (!ct.match(CommonContentTypes.APPLICATION_URLENCODED)) {
            throw new SerializeException("The HTTP Content-Type header must be " + CommonContentTypes.APPLICATION_URLENCODED);
        }

        Map<String, List<String>> params = httpRequest.getQueryParameters();

        params.putAll(toParameters());

        String queryString = URLUtils.serializeParameters(params);

        httpRequest.setQuery(queryString);
    }


    /**
     * Parses a client secret post authentication from the specified
     * parameters map. Note that the parameters must not be
     * {@code application/x-www-form-urlencoded} encoded.
     *
     * @param params The parameters map to parse. The client secret post
     *               parameters must be keyed under "client_id" and
     *               "client_secret". The map must not be {@code null}.
     * @return The client secret post authentication.
     * @throws OAuth2JSONParseException If the parameters map couldn't be parsed to a
     *                                  client secret post authentication.
     */
    public static ClientSecretPost parse(Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        String clientIDString = MultivaluedMapUtils.getFirstValue(params, "client_id");

        if (clientIDString == null) {
            throw new OAuth2JSONParseException("Malformed client secret post authentication: Missing \"client_id\" parameter");
        }

        String secretValue = MultivaluedMapUtils.getFirstValue(params, "client_secret");

        if (secretValue == null) {
            throw new OAuth2JSONParseException("Malformed client secret post authentication: Missing \"client_secret\" parameter");
        }

        return new ClientSecretPost(new ClientID(clientIDString), new Secret(secretValue));
    }


    /**
     * Parses a client secret post authentication from the specified
     * {@code application/x-www-form-urlencoded} encoded parameters string.
     *
     * @param paramsString The parameters string to parse. The client secret
     *                     post parameters must be keyed under "client_id"
     *                     and "client_secret". The string must not be
     *                     {@code null}.
     * @return The client secret post authentication.
     * @throws OAuth2JSONParseException If the parameters string couldn't be parsed to
     *                                  a client secret post authentication.
     */
    public static ClientSecretPost parse(String paramsString)
            throws OAuth2JSONParseException {

        Map<String, List<String>> params = URLUtils.parseParameters(paramsString);

        return parse(params);
    }


    /**
     * Parses a client secret post authentication from the specified HTTP
     * POST request.
     *
     * @param httpRequest The HTTP POST request to parse. Must not be
     *                    {@code null} and must contain a valid
     *                    {@code application/x-www-form-urlencoded} encoded
     *                    parameters string in the entity body. The client
     *                    secret post parameters must be keyed under
     *                    "client_id" and "client_secret".
     * @return The client secret post authentication.
     * @throws OAuth2JSONParseException If the HTTP request header couldn't be parsed
     *                                  to a valid client secret post authentication.
     */
    public static ClientSecretPost parse(HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        httpRequest.ensureMethod(HTTPRequest.Method.POST);
        httpRequest.ensureContentType(CommonContentTypes.APPLICATION_URLENCODED);

        return parse(httpRequest.getQueryParameters());
    }
}
