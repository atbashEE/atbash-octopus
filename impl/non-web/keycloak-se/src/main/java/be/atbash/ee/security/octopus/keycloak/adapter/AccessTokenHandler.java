/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.keycloak.adapter;

import org.keycloak.RSATokenVerifier;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.OIDCAuthenticationError;
import org.keycloak.common.VerificationException;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 */
final class AccessTokenHandler {

    private static final Logger logger = LoggerFactory.getLogger(AccessTokenHandler.class);

    private AccessTokenHandler() {
    }

    static KeycloakUserToken extractUser(KeycloakDeployment deployment, AccessTokenResponse accessTokenResponse) {
        String idTokenString = accessTokenResponse.getIdToken();
        AccessToken accessToken;
        IDToken idToken = null;
        try {
            accessToken = RSATokenVerifier.verifyToken(accessTokenResponse.getToken(), deployment.getRealmKey(), deployment.getRealmInfoUrl());
            if (idTokenString != null) {
                try {
                    JWSInput input = new JWSInput(idTokenString);
                    idToken = input.readJsonContent(IDToken.class);
                } catch (JWSInputException e) {
                    throw new VerificationException(e.getMessage());
                }
            }
            logger.debug("Token Verification succeeded!");
        } catch (VerificationException e) {
            logger.error(String.format("Failed verification of token: %s", e.getMessage()));
            throw new OIDCAuthenticationException(OIDCAuthenticationError.Reason.INVALID_TOKEN);

        }

        if (accessTokenResponse.getNotBeforePolicy() > deployment.getNotBefore()) {
            deployment.setNotBefore(accessTokenResponse.getNotBeforePolicy());
        }
        if (accessToken.getIssuedAt() < deployment.getNotBefore()) {
            logger.error("Stale token");
            throw new OIDCAuthenticationException(OIDCAuthenticationError.Reason.STALE_TOKEN);
        }

        // For safety, idToken cannot ever be null I guess.
        if (idToken == null) {
            throw new OIDCAuthenticationException(OIDCAuthenticationError.Reason.CODE_TO_TOKEN_FAILURE);
        }

        KeycloakUserToken user = KeycloakUserToken.fromIdToken(accessTokenResponse, idToken);

        // TODO Seems that roles aren't available in idToken only in accessToken
        user.setRoles(accessToken.getRealmAccess().getRoles());
        user.setClientSession(accessToken.getClientSession());

        // TODO Other parameters

        return user;
    }
}
