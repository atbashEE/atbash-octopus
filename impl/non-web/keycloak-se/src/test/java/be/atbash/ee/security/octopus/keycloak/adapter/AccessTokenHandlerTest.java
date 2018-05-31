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

import be.atbash.ee.security.octopus.jwt.JWTEncoding;
import be.atbash.ee.security.octopus.jwt.encoder.JWTEncoder;
import be.atbash.ee.security.octopus.jwt.parameter.JWTParametersBuilder;
import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.SecretKeyType;
import be.atbash.ee.security.octopus.keys.selector.filter.SecretKeyTypeKeyFilter;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.jwk.KeyType;
import org.junit.After;
import org.junit.Test;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.adapters.config.AdapterConfig;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import java.security.PublicKey;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class AccessTokenHandlerTest {

    private static final String ROLE1 = "role1";
    private static final String ROLE2 = "role2";
    private static final String CLIENT_SESSION = "clientSession";

    private TestLogger logger = TestLoggerFactory.getTestLogger(AccessTokenHandler.class);

    @After
    public void clearLoggers() {
        TestLoggerFactory.clear();
    }

    @Test
    public void extractUser_happyCase() {

        AccessToken accessToken = defineAccessToken();

        // generate RSA keys.
        List<AtbashKey> atbashKeys = defineRSAKey();

        // create JWT for AccessToken
        AtbashKey atbashKey = getPrivateKey(atbashKeys);

        JWTParametersBuilder builder = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS);
        builder.withSecretKeyForSigning(atbashKey);

        JWTEncoder encoder = new JWTEncoder();
        String jsonToken = encoder.encode(accessToken, builder.build());

        // Just create an empty IdToken, testing reading idToken is done somewhere else.
        String jsonIdToken = encoder.encode(new IDToken(), builder.build());

        // Create the AccessTokenResponse
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setToken(jsonToken);
        tokenResponse.setIdToken(jsonIdToken);
        tokenResponse.setSessionState(CLIENT_SESSION);

        // Create a KeycloakDeployment dummy.
        KeycloakDeployment deployment = defineKeycloakDeployment(atbashKeys);

        KeycloakUserToken user = AccessTokenHandler.extractUser(deployment, tokenResponse);

        // The fact we don't have an exception is already one very good thing :)

        assertThat(user.getRoles()).containsOnly(ROLE1, ROLE2);
        assertThat(user.getClientSession()).isEqualTo(CLIENT_SESSION);
    }

    @Test(expected = OIDCAuthenticationException.class)
    public void extractUser_AccessTokenValidationProblem() {

        AccessToken accessToken = defineAccessToken();
        accessToken.setSubject(null); // This will trigger an exception within RSATokenVerifier.verifyToken

        // generate RSA keys.
        List<AtbashKey> atbashKeys = defineRSAKey();

        // create JWT for AccessToken
        AtbashKey atbashKey = getPrivateKey(atbashKeys);

        JWTParametersBuilder builder = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS);
        builder.withSecretKeyForSigning(atbashKey);

        JWTEncoder encoder = new JWTEncoder();
        String jsonToken = encoder.encode(accessToken, builder.build());

        // Just create an empty IdToken, testing reading idToken is done somewhere else.
        String jsonIdToken = encoder.encode(new IDToken(), builder.build());

        // Create the AccessTokenResponse
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setToken(jsonToken);
        tokenResponse.setIdToken(jsonIdToken);

        // Create a KeycloakDeployment dummy.
        KeycloakDeployment deployment = defineKeycloakDeployment(atbashKeys);

        try {
            AccessTokenHandler.extractUser(deployment, tokenResponse);
        } finally {
            assertThat(logger.getLoggingEvents()).hasSize(1);
            assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Failed verification of token: Token user was null.");
        }

    }

    @Test(expected = OIDCAuthenticationException.class)
    public void extractUser_IdTokenInvalid() {

        AccessToken accessToken = defineAccessToken();

        // generate RSA keys.
        List<AtbashKey> atbashKeys = defineRSAKey();

        // create JWT for AccessToken
        AtbashKey atbashKey = getPrivateKey(atbashKeys);

        JWTParametersBuilder builder = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS);
        builder.withSecretKeyForSigning(atbashKey);

        JWTEncoder encoder = new JWTEncoder();
        String jsonToken = encoder.encode(accessToken, builder.build());

        // Create the AccessTokenResponse
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setToken(jsonToken);
        tokenResponse.setIdToken("{}");  // Obvious not a valid JWT :)

        // Create a KeycloakDeployment dummy.
        KeycloakDeployment deployment = defineKeycloakDeployment(atbashKeys);

        try {
            AccessTokenHandler.extractUser(deployment, tokenResponse);
        } finally {
            assertThat(logger.getLoggingEvents()).hasSize(1);
            assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Failed verification of token: java.lang.IllegalArgumentException: Parsing error");
        }

    }

    @Test(expected = OIDCAuthenticationException.class)
    public void extractUser_StaleToken() {

        AccessToken accessToken = defineAccessToken();

        // generate RSA keys.
        List<AtbashKey> atbashKeys = defineRSAKey();

        // create JWT for AccessToken
        AtbashKey atbashKey = getPrivateKey(atbashKeys);

        JWTParametersBuilder builder = JWTParametersBuilder.newBuilderFor(JWTEncoding.JWS);
        builder.withSecretKeyForSigning(atbashKey);

        JWTEncoder encoder = new JWTEncoder();
        String jsonToken = encoder.encode(accessToken, builder.build());

        // Just create an empty IdToken, testing reading idToken is done somewhere else.
        String jsonIdToken = encoder.encode(new IDToken(), builder.build());

        // Create the AccessTokenResponse
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setToken(jsonToken);
        tokenResponse.setIdToken(jsonIdToken);

        // Create a KeycloakDeployment dummy.
        KeycloakDeployment deployment = defineKeycloakDeployment(atbashKeys);
        deployment.setNotBefore(100);  // token issuedAt has 0 as time, so it is older and trigger exception.

        try {
            AccessTokenHandler.extractUser(deployment, tokenResponse);
        } finally {
            assertThat(logger.getLoggingEvents()).hasSize(2);

            // 0 debug message validation of tokens went OK.
            assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.DEBUG);

            // 1 Error
            assertThat(logger.getLoggingEvents().get(1).getLevel()).isEqualTo(Level.ERROR);
            assertThat(logger.getLoggingEvents().get(1).getMessage()).isEqualTo("Stale token");
        }

    }

    private KeycloakDeployment defineKeycloakDeployment(List<AtbashKey> atbashKeys) {
        KeycloakDeployment deployment = new KeycloakDeployment();
        deployment.setRealmKey((PublicKey) atbashKeys.get(0).getKey());
        deployment.setRealm("test");
        AdapterConfig config = new AdapterConfig();
        config.setAuthServerUrl("http://localhost/auth");
        deployment.setAuthServerBaseUrl(config);
        return deployment;
    }

    private List<AtbashKey> defineRSAKey() {
        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId("Test")
                .build();
        KeyGenerator generator = new KeyGenerator();
        return generator.generateKeys(generationParameters);
    }

    private AccessToken defineAccessToken() {
        AccessToken accessToken = new AccessToken();
        // Required values for the verifier
        accessToken.setSubject("Atbash");
        accessToken.issuer("http://localhost/auth/realms/test");
        accessToken.type("Bearer");

        // Values for the things we want to test here.
        AccessToken.Access realmAccess = new AccessToken.Access();
        realmAccess.addRole(ROLE1);
        realmAccess.addRole(ROLE2);
        accessToken.setRealmAccess(realmAccess);
        return accessToken;
    }

    private AtbashKey getPrivateKey(List<AtbashKey> atbashKeys) {
        List<AtbashKey> keys = new SecretKeyTypeKeyFilter(new SecretKeyType(KeyType.RSA, AsymmetricPart.PRIVATE)).filter(atbashKeys);
        if (keys.size() != 1) {
            throw new AtbashUnexpectedException("Could not find the RSA Private key");
        }
        return keys.get(0);
    }

    private AtbashKey getPublicKey(List<AtbashKey> atbashKeys) {
        List<AtbashKey> keys = new SecretKeyTypeKeyFilter(new SecretKeyType(KeyType.RSA, AsymmetricPart.PUBLIC)).filter(atbashKeys);
        if (keys.size() != 1) {
            throw new AtbashUnexpectedException("Could not find the RSA Public key");
        }
        return keys.get(0);
    }
}