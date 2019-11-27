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


import be.atbash.ee.oauth2.sdk.token.RefreshToken;
import be.atbash.ee.oauth2.sdk.util.MultivaluedMapUtils;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;


/**
 * Refresh token grant. Used in refresh token requests.
 *
 * <p>Note that the optional scope parameter is not supported.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>OAuth 2.0 (RFC 6749), section 6.
 * </ul>
 */
public class RefreshTokenGrant extends AuthorizationGrant {


    /**
     * The grant type.
     */
    public static final GrantType GRANT_TYPE = GrantType.REFRESH_TOKEN;


    /**
     * The refresh token.
     */
    private final RefreshToken refreshToken;


    /**
     * Creates a new refresh token grant.
     *
     * @param refreshToken The refresh token. Must not be {@code null}.
     */
    public RefreshTokenGrant(RefreshToken refreshToken) {


        super(GRANT_TYPE);

        if (refreshToken == null) {
            throw new IllegalArgumentException("The refresh token must not be null");
        }

        this.refreshToken = refreshToken;
    }


    /**
     * Gets the refresh token.
     *
     * @return The refresh token.
     */
    public RefreshToken getRefreshToken() {

        return refreshToken;
    }


    @Override
    public Map<String, List<String>> toParameters() {

        Map<String, List<String>> params = new LinkedHashMap<>();
        params.put("grant_type", Collections.singletonList(GRANT_TYPE.getValue()));
        params.put("refresh_token", Collections.singletonList(refreshToken.getValue()));
        return params;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        RefreshTokenGrant grant = (RefreshTokenGrant) o;

        return refreshToken.equals(grant.refreshToken);

    }


    @Override
    public int hashCode() {
        return refreshToken.hashCode();
    }


    /**
     * Parses a refresh token grant from the specified request body
     * parameters.
     *
     * <p>Example:
     *
     * <pre>
     * grant_type=refresh_token
     * refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
     * </pre>
     *
     * @param params The parameters.
     * @return The refresh token grant.
     * @throws OAuth2JSONParseException If parsing failed.
     */
    public static RefreshTokenGrant parse(Map<String, List<String>> params)
            throws OAuth2JSONParseException {

        // Parse grant type
        String grantTypeString = MultivaluedMapUtils.getFirstValue(params, "grant_type");

        if (grantTypeString == null) {
            String msg = "Missing \"grant_type\" parameter";
            throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
        }

        if (!GrantType.parse(grantTypeString).equals(GRANT_TYPE)) {
            String msg = "The \"grant_type\" must be \"" + GRANT_TYPE + "\"";
            throw new OAuth2JSONParseException(msg, OAuth2Error.UNSUPPORTED_GRANT_TYPE.appendDescription(": " + msg));
        }

        // Parse refresh token
        String refreshTokenString = MultivaluedMapUtils.getFirstValue(params, "refresh_token");

        if (refreshTokenString == null || refreshTokenString.trim().isEmpty()) {
            String msg = "Missing or empty \"refresh_token\" parameter";
            throw new OAuth2JSONParseException(msg, OAuth2Error.INVALID_REQUEST.appendDescription(": " + msg));
        }

        RefreshToken refreshToken = new RefreshToken(refreshTokenString);

        return new RefreshTokenGrant(refreshToken);
    }
}
