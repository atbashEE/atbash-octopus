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
package be.atbash.ee.openid.connect.sdk.rp;


import be.atbash.ee.oauth2.sdk.OAuth2JSONParseException;
import be.atbash.ee.oauth2.sdk.auth.Secret;
import be.atbash.ee.oauth2.sdk.client.ClientCredentialsParser;
import be.atbash.ee.oauth2.sdk.client.ClientInformation;
import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;

import javax.json.JsonObject;
import java.net.URI;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;


/**
 * OpenID Connect client information. Encapsulates the registration and
 * metadata details of an OpenID Connect client:
 *
 * <ul>
 *     <li>The client identifier.
 *     <li>The client OpenID Connect metadata.
 *     <li>The optional client secret for a confidential client.
 *     <li>The optional registration URI and access token if dynamic client
 *         registration is permitted.
 * </ul>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), section
 *         3.2.1.
 *     <li>OAuth 2.0 Dynamic Client Registration Management Protocol (RFC
 *         7592), section 3.
 * </ul>
 */
public final class OIDCClientInformation extends ClientInformation {


    /**
     * The registered parameter names.
     */
    private static final Set<String> REGISTERED_PARAMETER_NAMES;


    static {
        Set<String> p = new HashSet<>(ClientInformation.getRegisteredParameterNames());
        p.addAll(OIDCClientMetadata.getRegisteredParameterNames());
        REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
    }


    /**
     * Creates a new OpenID Connect client information instance.
     *
     * @param id        The client identifier. Must not be {@code null}.
     * @param issueDate The issue date of the client identifier,
     *                  {@code null} if not specified.
     * @param metadata  The OpenID Connect client metadata. Must not be
     *                  {@code null}.
     * @param secret    The optional client secret, {@code null} if not
     *                  specified.
     */
    public OIDCClientInformation(final ClientID id,
                                 final Date issueDate,
                                 final OIDCClientMetadata metadata,
                                 final Secret secret) {

        this(id, issueDate, metadata, secret, null, null);
    }


    /**
     * Creates a new OpenID Connect client information instance permitting
     * dynamic client registration management.
     *
     * @param id              The client identifier. Must not be
     *                        {@code null}.
     * @param issueDate       The issue date of the client identifier,
     *                        {@code null} if not specified.
     * @param metadata        The OpenID Connect client metadata. Must not
     *                        be {@code null}.
     * @param secret          The optional client secret, {@code null} if
     *                        not specified.
     * @param registrationURI The client registration URI, {@code null} if
     *                        not specified.
     * @param accessToken     The client registration access token,
     *                        {@code null} if not specified.
     */
    public OIDCClientInformation(final ClientID id,
                                 final Date issueDate,
                                 final OIDCClientMetadata metadata,
                                 final Secret secret,
                                 final URI registrationURI,
                                 final BearerAccessToken accessToken) {

        super(id, issueDate, metadata, secret, registrationURI, accessToken);
    }


    /**
     * Gets the registered client metadata parameter names.
     *
     * @return The registered parameter names, as an unmodifiable set.
     */
    public static Set<String> getRegisteredParameterNames() {

        return REGISTERED_PARAMETER_NAMES;
    }


    /**
     * Gets the OpenID Connect client metadata.
     *
     * @return The OpenID Connect client metadata.
     */
    public OIDCClientMetadata getOIDCMetadata() {

        return (OIDCClientMetadata) getMetadata();
    }


    /**
     * Parses an OpenID Connect client information instance from the
     * specified JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be
     *                   {@code null}.
     * @return The client information.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to an
     *                                  OpenID Connect client information instance.
     */
    public static OIDCClientInformation parse(final JsonObject jsonObject)
            throws OAuth2JSONParseException {

        return new OIDCClientInformation(
                ClientCredentialsParser.parseID(jsonObject),
                ClientCredentialsParser.parseIDIssueDate(jsonObject),
                OIDCClientMetadata.parse(jsonObject),
                ClientCredentialsParser.parseSecret(jsonObject),
                ClientCredentialsParser.parseRegistrationURI(jsonObject),
                ClientCredentialsParser.parseRegistrationAccessToken(jsonObject));
    }
}
