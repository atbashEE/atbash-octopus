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
package be.atbash.ee.oauth2.sdk;


import be.atbash.ee.oauth2.sdk.auth.X509CertificateConfirmation;
import be.atbash.ee.oauth2.sdk.http.CommonContentTypes;
import be.atbash.ee.oauth2.sdk.http.HTTPResponse;
import be.atbash.ee.oauth2.sdk.id.*;
import be.atbash.ee.oauth2.sdk.token.AccessTokenType;
import be.atbash.ee.security.octopus.nimbus.jwt.util.DateUtils;
import be.atbash.ee.security.octopus.nimbus.util.Base64URLValue;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Map;


/**
 * Token introspection success response.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 Token Introspection (RFC 7662).
 *     <li>OAuth 2.0 Mutual TLS Client Authentication and Certificate Bound
 *         Access Tokens (draft-ietf-oauth-mtls-15).
 * </ul>
 */
public class TokenIntrospectionSuccessResponse extends TokenIntrospectionResponse implements SuccessResponse {


    /**
     * Builder for constructing token introspection success responses.
     */
    public static class Builder {


        /**
         * The parameters.
         */
        private final JsonObjectBuilder params = Json.createObjectBuilder();


        /**
         * Creates a new token introspection success response builder.
         *
         * @param active {@code true} if the token is active, else
         *               {@code false}.
         */
        public Builder(final boolean active) {

            params.add("active", active);
        }


        /**
         * Creates a new token introspection success response builder
         * with the parameters of the specified response.
         *
         * @param response The response which parameters to use. Not
         *                 {@code null}.
         */
        public Builder(final TokenIntrospectionSuccessResponse response) {

            params.addAll(Json.createObjectBuilder(response.params));
        }


        /**
         * Sets the token scope.
         *
         * @param scope The token scope, {@code null} if not specified.
         * @return This builder.
         */
        public Builder scope(final Scope scope) {
            if (scope != null) {
                params.add("scope", scope.toString());
            } else {
                params.remove("scope");
            }
            return this;
        }


        /**
         * Sets the identifier for the OAuth 2.0 client that requested
         * the token.
         *
         * @param clientID The client identifier, {@code null} if not
         *                 specified.
         * @return This builder.
         */
        public Builder clientID(final ClientID clientID) {
            if (clientID != null) {
                params.add("client_id", clientID.getValue());
            } else {
                params.remove("client_id");
            }
            return this;
        }


        /**
         * Sets the username of the resource owner who authorised the
         * token.
         *
         * @param username The username, {@code null} if not specified.
         * @return This builder.
         */
        public Builder username(final String username) {
            if (username != null) {
                params.add("username", username);
            } else {
                params.remove("username");
            }
            return this;
        }


        /**
         * Sets the token type.
         *
         * @param tokenType The token type, {@code null} if not
         *                  specified.
         * @return This builder.
         */
        public Builder tokenType(final AccessTokenType tokenType) {
            if (tokenType != null) {
                params.add("token_type", tokenType.getValue());
            } else {
                params.remove("token_type");
            }
            return this;
        }


        /**
         * Sets the token expiration time.
         *
         * @param exp The token expiration time, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder expirationTime(final Date exp) {
            if (exp != null) {
                params.add("exp", DateUtils.toSecondsSinceEpoch(exp));
            } else {
                params.remove("exp");
            }
            return this;
        }


        /**
         * Sets the token issue time.
         *
         * @param iat The token issue time, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder issueTime(final Date iat) {
            if (iat != null) {
                params.add("iat", DateUtils.toSecondsSinceEpoch(iat));
            } else {
                params.remove("iat");
            }
            return this;
        }


        /**
         * Sets the token not-before time.
         *
         * @param nbf The token not-before time, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder notBeforeTime(final Date nbf) {
            if (nbf != null) {
                params.add("nbf", DateUtils.toSecondsSinceEpoch(nbf));
            } else {
                params.remove("nbf");
            }
            return this;
        }


        /**
         * Sets the token subject.
         *
         * @param sub The token subject, {@code null} if not specified.
         * @return This builder.
         */
        public Builder subject(final Subject sub) {
            if (sub != null) {
                params.add("sub", sub.getValue());
            } else {
                params.remove("sub");
            }
            return this;
        }


        /**
         * Sets the token audience.
         *
         * @param audList The token audience, {@code null} if not
         *                specified.
         * @return This builder.
         */
        public Builder audience(final List<Audience> audList) {
            if (audList != null) {
                params.add("aud", JSONObjectUtils.asJsonArray(Audience.toStringList(audList)));
            } else {
                params.remove("aud");
            }
            return this;
        }


        /**
         * Sets the token issuer.
         *
         * @param iss The token issuer, {@code null} if not specified.
         * @return This builder.
         */
        public Builder issuer(final Issuer iss) {
            if (iss != null) {
                params.add("iss", iss.getValue());
            } else {
                params.remove("iss");
            }
            return this;
        }


        /**
         * Sets the token identifier.
         *
         * @param jti The token identifier, {@code null} if not
         *            specified.
         * @return This builder.
         */
        public Builder jwtID(final JWTID jti) {
            if (jti != null) {
                params.add("jti", jti.getValue());
            } else {
                params.remove("jti");
            }
            return this;
        }


        /**
         * Sets the client X.509 certificate SHA-256 thumbprint, for a
         * mutual TLS client certificate bound access token.
         * Corresponds to the {@code cnf.x5t#S256} claim.
         *
         * @param x5t The client X.509 certificate SHA-256 thumbprint,
         *            {@code null} if not specified.
         * @return This builder.
         */
        @Deprecated
        public Builder x509CertificateSHA256Thumbprint(final Base64URLValue x5t) {

            /*
            if (x5t != null) {
                JsonObject cnf;
                if (params.containsKey("cnf")) {
                    cnf = (JSONObject) params.get("cnf");
                } else {
                    cnf = new JSONObject();
                    params.put("cnf", cnf);
                }
                cnf.put("x5t#S256", x5t.toString());
            } else if (params.containsKey("cnf")) {
                JSONObject cnf = (JSONObject) params.get("cnf");
                cnf.remove("x5t#S256");
                if (cnf.isEmpty()) {
                    params.remove("cnf");
                }
            }

            return this;

             */
            // FIXME
            throw new IllegalArgumentException("Not yet converted");
        }


        /**
         * Sets the client X.509 certificate confirmation, for a mutual
         * TLS client certificate bound access token. Corresponds to
         * the {@code cnf.x5t#S256} claim.
         *
         * @param cnf The client X.509 certificate confirmation,
         *            {@code null} if not specified.
         * @return This builder.
         */
        public Builder x509CertificateConfirmation(final X509CertificateConfirmation cnf) {

            if (cnf != null) {
                Map.Entry<String, JsonObject> param = cnf.toJWTClaim();
                params.add(param.getKey(), param.getValue());
            } else {
                params.remove("cnf");
            }
            return this;
        }


        /**
         * Sets a custom parameter.
         *
         * @param name  The parameter name. Must not be {@code null}.
         * @param value The parameter value. Should map to a JSON type.
         *              If {@code null} not specified.
         * @return This builder.
         */
        public Builder parameter(final String name, final Object value) {
            if (value != null) {
                JSONObjectUtils.addValue(params, name, value);
            } else {
                params.remove(name);
            }
            return this;
        }


        /**
         * Builds a new token introspection success response.
         *
         * @return The token introspection success response.
         */
        public TokenIntrospectionSuccessResponse build() {

            return new TokenIntrospectionSuccessResponse(params.build());
        }
    }


    /**
     * The parameters.
     */
    private final JsonObject params;


    /**
     * Creates a new token introspection success response.
     *
     * @param params The response parameters. Must contain at least the
     *               required {@code active} parameter and not be
     *               {@code null}.
     */
    public TokenIntrospectionSuccessResponse(final JsonObject params) {

        if (!(JSONObjectUtils.getJsonValueAsObject(params.get("active")) instanceof Boolean)) {
            throw new IllegalArgumentException("Missing / invalid boolean active parameter");
        }

        this.params = Json.createObjectBuilder(params).build();
    }


    /**
     * Returns the active status for the token. Corresponds to the
     * {@code active} claim.
     *
     * @return {@code true} if the token is active, else {@code false}.
     */
    public boolean isActive() {

        return params.getBoolean("active", false);
    }


    /**
     * Returns the scope of the token. Corresponds to the {@code scope}
     * claim.
     *
     * @return The token scope, {@code null} if not specified.
     */
    public Scope getScope() {

        return Scope.parse(params.getString("scope"));
    }


    /**
     * Returns the identifier of the OAuth 2.0 client that requested the
     * token. Corresponds to the {@code client_id} claim.
     *
     * @return The client identifier, {@code null} if not specified.
     */
    public ClientID getClientID() {

        return new ClientID(params.getString("client_id"));
    }


    /**
     * Returns the username of the resource owner who authorised the token.
     * Corresponds to the {@code username} claim.
     *
     * @return The username, {@code null} if not specified.
     */
    public String getUsername() {

        return params.getString("username", null);
    }


    /**
     * Returns the access token type. Corresponds to the {@code token_type}
     * claim.
     *
     * @return The token type, {@code null} if not specified.
     */
    public AccessTokenType getTokenType() {

        return new AccessTokenType(params.getString("token_type"));
    }


    /**
     * Returns the token expiration time. Corresponds to the {@code exp}
     * claim.
     *
     * @return The token expiration time, {@code null} if not specified.
     */
    public Date getExpirationTime() {

        return DateUtils.fromSecondsSinceEpoch(params.getJsonNumber("exp").longValue());
    }


    /**
     * Returns the token issue time. Corresponds to the {@code iat} claim.
     *
     * @return The token issue time, {@code null} if not specified.
     */
    public Date getIssueTime() {

        return DateUtils.fromSecondsSinceEpoch(params.getJsonNumber("iat").longValue());
    }


    /**
     * Returns the token not-before time. Corresponds to the {@code nbf}
     * claim.
     *
     * @return The token not-before time, {@code null} if not specified.
     */
    public Date getNotBeforeTime() {

        return DateUtils.fromSecondsSinceEpoch(params.getJsonNumber("nbf").longValue());
    }


    /**
     * Returns the subject of the token, usually a machine-readable
     * identifier of the resource owner who authorised the token.
     * Corresponds to the {@code sub} claim.
     *
     * @return The token subject, {@code null} if not specified.
     */
    public Subject getSubject() {

        return new Subject(params.getString("sub"));
    }


    /**
     * Returns the intended audience for the token. Corresponds to the
     * {@code aud} claim.
     *
     * @return The token audience, {@code null} if not specified.
     */
    public List<Audience> getAudience() {
        // Try string array first, then string
        if (params.get("aud").getValueType() == JsonValue.ValueType.ARRAY) {
            return Audience.create(JSONObjectUtils.getStringList(params, "aud"));

        } else {
            return new Audience(params.getString("aud")).toSingleAudienceList();

        }
    }


    /**
     * Returns the token issuer. Corresponds to the {@code iss} claim.
     *
     * @return The token issuer, {@code null} if not specified.
     */
    public Issuer getIssuer() {

        return new Issuer(params.getString("iss"));
    }


    /**
     * Returns the token identifier. Corresponds to the {@code jti}
     * claim.
     *
     * @return The token identifier, {@code null} if not specified.
     */
    public JWTID getJWTID() {

        return new JWTID(params.getString("jti"));
    }


    /**
     * Returns the client X.509 certificate SHA-256 thumbprint, for a
     * mutual TLS client certificate bound access token. Corresponds to the
     * {@code cnf.x5t#S256} claim.
     *
     * @return The client X.509 certificate SHA-256 thumbprint,
     * {@code null} if not specified.
     */
    @Deprecated
    public Base64URLValue getX509CertificateSHA256Thumbprint() {

        JsonObject cnf = params.getJsonObject("cnf");

        if (cnf == null) {
            return null;
        }

        String x5t = cnf.getString("x5t#S256", null);

        if (x5t == null) {
            return null;
        }

        return new Base64URLValue(x5t);

    }


    /**
     * Returns the client X.509 certificate confirmation, for a mutual TLS
     * client certificate bound access token. Corresponds to the
     * {@code cnf.x5t#S256} claim.
     *
     * @return The client X.509 certificate confirmation, {@code null} if
     * not specified.
     */
    public X509CertificateConfirmation getX509CertificateConfirmation() {

        return X509CertificateConfirmation.parse(params);
    }


    /**
     * Returns the string parameter with the specified name.
     *
     * @param name The parameter name. Must not be {@code null}.
     * @return The parameter value, {@code null} if not specified or if
     * parsing failed.
     */
    public String getStringParameter(final String name) {

        return params.getString(name, null);
    }


    /**
     * Returns the boolean parameter with the specified name.
     *
     * @param name The parameter name. Must not be {@code null}.
     * @return The parameter value.
     */
    public boolean getBooleanParameter(final String name) {

        return params.getBoolean(name);
    }


    /**
     * Returns the number parameter with the specified name.
     *
     * @param name The parameter name. Must not be {@code null}.
     * @return The parameter value, {@code null} if not specified or
     * parsing failed.
     */
    public Number getNumberParameter(final String name) {

        return params.getJsonNumber(name).numberValue();
    }


    /**
     * Returns the string list parameter with the specified name.
     *
     * @param name The parameter name. Must not be {@code null}.
     * @return The parameter value, {@code null} if not specified or if
     * parsing failed.
     */
    public List<String> getStringListParameter(final String name) {

        return JSONObjectUtils.getStringList(params, name);
    }


    /**
     * Returns the JSON object parameter with the specified name.
     *
     * @param name The parameter name. Must not be {@code null}.
     * @return The parameter value, {@code null} if not specified or if
     * parsing failed.
     */
    public JsonObject getJSONObjectParameter(final String name) {

        return params.getJsonObject(name);
    }


    /**
     * Returns the underlying parameters.
     *
     * @return The parameters, as JSON object.
     */
    public JsonObject getParameters() {

        return params;
    }


    /**
     * Returns a JSON object representation of this token introspection
     * success response.
     *
     * <p>Example JSON object:
     *
     * <pre>
     * {
     *  "active"          : true,
     *  "client_id"       : "l238j323ds-23ij4",
     *  "username"        : "jdoe",
     *  "scope"           : "read write dolphin",
     *  "sub"             : "Z5O3upPC88QrAjx00dis",
     *  "aud"             : "https://protected.example.net/resource",
     *  "iss"             : "https://server.example.com/",
     *  "exp"             : 1419356238,
     *  "iat"             : 1419350238,
     *  "extension_field" : "twenty-seven"
     * }
     * </pre>
     *
     * @return The JSON object.
     */
    public JsonObject toJSONObject() {

        return params;
    }


    @Override
    public boolean indicatesSuccess() {

        return true;
    }


    @Override
    public HTTPResponse toHTTPResponse() {

        HTTPResponse httpResponse = new HTTPResponse(HTTPResponse.SC_OK);
        httpResponse.setContentType(CommonContentTypes.APPLICATION_JSON);
        httpResponse.setContent(params.toString());
        return httpResponse;
    }


    /**
     * Parses a token introspection success response from the specified
     * JSON object.
     *
     * @param jsonObject The JSON object to parse. Must not be {@code null}.
     * @return The token introspection success response.
     * @throws OAuth2JSONParseException If the JSON object couldn't be parsed to a
     *                                  token introspection success response.
     */
    public static TokenIntrospectionSuccessResponse parse(final JsonObject jsonObject)
            throws OAuth2JSONParseException {

        try {
            return new TokenIntrospectionSuccessResponse(jsonObject);
        } catch (IllegalArgumentException e) {
            throw new OAuth2JSONParseException(e.getMessage(), e);
        }
    }


    /**
     * Parses an token introspection success response from the specified
     * HTTP response.
     *
     * @param httpResponse The HTTP response. Must not be {@code null}.
     * @return The token introspection success response.
     * @throws ParseException If the HTTP response couldn't be parsed to a
     *                        token introspection success response.
     */
    public static TokenIntrospectionSuccessResponse parse(final HTTPResponse httpResponse)
            throws OAuth2JSONParseException {

        httpResponse.ensureStatusCode(HTTPResponse.SC_OK);
        JsonObject jsonObject = httpResponse.getContentAsJSONObject();
        return parse(jsonObject);
    }
}
