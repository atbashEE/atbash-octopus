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
import be.atbash.ee.oauth2.sdk.client.ClientRegistrationRequest;
import be.atbash.ee.oauth2.sdk.http.HTTPRequest;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.security.octopus.nimbus.jwt.SignedJWT;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.util.StringUtils;

import javax.json.JsonObject;
import java.net.URI;
import java.net.URISyntaxException;


/**
 * OpenID Connect client registration request.
 *
 * <p>Example HTTP request:
 *
 * <pre>
 * POST /connect/register HTTP/1.1
 * Content-Type: application/json
 * Accept: application/json
 * Host: server.example.com
 * Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.eyJ ...
 *
 * {
 *  "application_type"                : "web",
 *  "redirect_uris"                   : [ "https://client.example.org/callback",
 *                                        "https://client.example.org/callback2" ],
 *  "client_name"                     : "My Example",
 *  "client_name#ja-Jpan-JP"          : "クライアント名",
 *  "logo_uri"                        : "https://client.example.org/logo.png",
 *  "subject_type"                    : "pairwise",
 *  "sector_identifier_uri"           : "https://other.example.net/file_of_redirect_uris.json",
 *  "token_endpoint_auth_method"      : "client_secret_basic",
 *  "jwks_uri"                        : "https://client.example.org/my_public_keys.jwks",
 *  "userinfo_encrypted_response_alg" : "RSA1_5",
 *  "userinfo_encrypted_response_enc" : "A128CBC-HS256",
 *  "contacts"                        : [ "ve7jtb@example.org", "mary@example.org" ],
 *  "request_uris"                    : [ "https://client.example.org/rf.txt#qpXaRLh_n93TTR9F252ValdatUQvQiJi5BDub2BeznA" ]
 * }
 * </pre>
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OpenID Connect Dynamic Client Registration 1.0, section 3.1.
 *     <li>OAuth 2.0 Dynamic Client Registration Protocol (RFC 7591), sections
 *         2 and 3.1.
 * </ul>
 */
// FIXME Will this be used in Octopus?
public class OIDCClientRegistrationRequest extends ClientRegistrationRequest {


    /**
     * Creates a new OpenID Connect client registration request.
     *
     * @param uri         The URI of the client registration endpoint. May
     *                    be {@code null} if the {@link #toHTTPRequest()}
     *                    method will not be used.
     * @param metadata    The OpenID Connect client metadata. Must not be
     *                    {@code null} and must specify one or more
     *                    redirection URIs.
     * @param accessToken An OAuth 2.0 Bearer access token for the request,
     *                    {@code null} if none.
     */
    public OIDCClientRegistrationRequest(final URI uri,
                                         final OIDCClientMetadata metadata,
                                         final BearerAccessToken accessToken) {

        super(uri, metadata, accessToken);
    }


    /**
     * Creates a new OpenID Connect client registration request with an
     * optional software statement.
     *
     * @param uri               The URI of the client registration
     *                          endpoint. May be {@code null} if the
     *                          {@link #toHTTPRequest()} method will not be
     *                          used.
     * @param metadata          The OpenID Connect client metadata. Must
     *                          not be {@code null} and must specify one or
     *                          more redirection URIs.
     * @param softwareStatement Optional software statement, as a signed
     *                          JWT with an {@code iss} claim; {@code null}
     *                          if not specified.
     * @param accessToken       An OAuth 2.0 Bearer access token for the
     *                          request, {@code null} if none.
     */
    public OIDCClientRegistrationRequest(final URI uri,
                                         final OIDCClientMetadata metadata,
                                         final SignedJWT softwareStatement,
                                         final BearerAccessToken accessToken) {

        super(uri, metadata, softwareStatement, accessToken);
    }


    /**
     * Gets the associated OpenID Connect client metadata.
     *
     * @return The OpenID Connect client metadata.
     */
    public OIDCClientMetadata getOIDCClientMetadata() {

        return (OIDCClientMetadata) getClientMetadata();
    }


    /**
     * Parses an OpenID Connect client registration request from the
     * specified HTTP POST request.
     *
     * @param httpRequest The HTTP request. Must not be {@code null}.
     * @return The OpenID Connect client registration request.
     * @throws OAuth2JSONParseException If the HTTP request couldn't be parsed to an
     *                                  OpenID Connect client registration request.
     */
    public static OIDCClientRegistrationRequest parse(final HTTPRequest httpRequest)
            throws OAuth2JSONParseException {

        httpRequest.ensureMethod(HTTPRequest.Method.POST);

        // Get the JSON object content
        JsonObject jsonObject = httpRequest.getQueryAsJSONObject();

        // Extract the software statement if any
        SignedJWT stmt = null;

        if (jsonObject.containsKey("software_statement")) {

            try {
                stmt = SignedJWT.parse(jsonObject.getString("software_statement"));

            } catch (java.text.ParseException e) {

                throw new OAuth2JSONParseException("Invalid software statement JWT: " + e.getMessage());
            }

            // Prevent the JWT from appearing in the metadata
            jsonObject = JSONObjectUtils.remove(jsonObject, "software_statement");
        }

        // Parse the client metadata
        OIDCClientMetadata metadata = OIDCClientMetadata.parse(jsonObject);

        // Parse the optional bearer access token
        BearerAccessToken accessToken = null;

        String authzHeaderValue = httpRequest.getAuthorization();

        if (StringUtils.hasText(authzHeaderValue)) {
            accessToken = BearerAccessToken.parse(authzHeaderValue);
        }

        try {
            URI endpointURI = httpRequest.getURL().toURI();

            return new OIDCClientRegistrationRequest(endpointURI, metadata, stmt, accessToken);

        } catch (URISyntaxException | IllegalArgumentException e) {

            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
    }
}
