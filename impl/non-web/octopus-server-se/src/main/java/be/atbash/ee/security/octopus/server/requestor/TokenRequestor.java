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
package be.atbash.ee.security.octopus.server.requestor;

import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.server.config.OctopusServerConfiguration;
import be.atbash.ee.security.octopus.server.debug.CorrelationCounter;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.util.ByteUtils;
import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretJWT;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 *  FIXME Move to octopus-oauth2-se ???
 *  Can it be used with a generic OAuth2 (like keyCloack)??
 */

public class TokenRequestor extends AbstractRequestor {

    private JWSAlgorithm algorithm;

    private TokenRequestor(OctopusCoreConfiguration coreConfiguration, OctopusServerConfiguration configuration) {
        setConfiguration(coreConfiguration,  configuration);
        init();
    }

    private void init() {
        byte[] ssoClientSecret = configuration.getSSOClientSecret();
        if (ssoClientSecret.length > 0) {
            Set<JWSAlgorithm> algorithms = MACSigner.getCompatibleAlgorithms(ByteUtils.bitLength(ssoClientSecret));

            if (algorithms.contains(JWSAlgorithm.HS512)) {
                algorithm = JWSAlgorithm.HS512;
            }
            if (algorithm == null && algorithms.contains(JWSAlgorithm.HS384)) {
                algorithm = JWSAlgorithm.HS384;
            }
            if (algorithm == null && algorithms.contains(JWSAlgorithm.HS256)) {
                algorithm = JWSAlgorithm.HS256;
            }
        }
    }

    public TokenResponse getToken(UsernamePasswordToken token) {
        TokenResponse result;
        AuthorizationGrant passwordGrant = new ResourceOwnerPasswordCredentialsGrant(token.getUsername(), new Secret(new String(token.getPassword())));  // TODO UTF-8 CHARSET? Password is char[]
        try {
            URI tokenEndPoint = new URI(configuration.getTokenEndpoint());

            TokenRequest tokenRequest;
            if (algorithm != null) {
                ClientAuthentication clientAuth = new ClientSecretJWT(new ClientID(configuration.getSSOClientId())
                        , tokenEndPoint, algorithm, new Secret(new String(configuration.getSSOClientSecret(), StandardCharsets.UTF_8)));
                tokenRequest = new TokenRequest(tokenEndPoint, clientAuth, passwordGrant, Scope.parse(configuration.getSSOScopes()));
            } else {
                tokenRequest = new TokenRequest(tokenEndPoint, passwordGrant, Scope.parse(configuration.getSSOScopes()));
            }

            HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
            int correlationId = -1;
            if (coreConfiguration.showDebugFor().contains(Debug.SSO_REST)) {
                correlationId = CorrelationCounter.VALUE.getAndIncrement();
                showRequest(correlationId, httpRequest);
            }

            HTTPResponse response;
            try {
                response = httpRequest.send();
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new AtbashUnexpectedException(String.format("Connection refused or exception calling %s. Exception message : %s", configuration.getTokenEndpoint(), e.getMessage()));

            }

            if (coreConfiguration.showDebugFor().contains(Debug.SSO_REST)) {
                showResponse(correlationId, response);
            }

            result = TokenResponse.parse(response);

            /*
            400
{"error_description":"Client authentication failed","error":"invalid_client"}

             */

        } catch (URISyntaxException e) {
            throw new AtbashUnexpectedException(String.format("Invalid URI for token endpoint (SSO.server parameter) %s. Exception message : %s", configuration.getTokenEndpoint(), e.getMessage()));
        } catch (ParseException | JOSEException e) {
            throw new AtbashUnexpectedException(e);
        }

        return result;
    }


    // Java SE Support
    private static TokenRequestor INSTANCE;

    private static final Object LOCK = new Object();

    public static TokenRequestor getInstance(OctopusCoreConfiguration coreConfiguration, OctopusServerConfiguration configuration) {
        if (INSTANCE == null) {
            synchronized (LOCK) {
                if (INSTANCE == null) {
                    INSTANCE = new TokenRequestor(coreConfiguration, configuration);
                }
            }
        }
        return INSTANCE;
    }


}
