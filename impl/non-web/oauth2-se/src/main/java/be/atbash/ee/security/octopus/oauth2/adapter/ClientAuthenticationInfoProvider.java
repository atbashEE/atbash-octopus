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
package be.atbash.ee.security.octopus.oauth2.adapter;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.authc.AuthenticationStrategy;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.sso.client.OpenIdVariableClientData;
import be.atbash.ee.security.octopus.sso.client.SSOAuthenticationInfoBuilder;
import be.atbash.ee.security.octopus.sso.client.config.OctopusSSOServerClientConfiguration;
import be.atbash.ee.security.octopus.sso.client.requestor.OctopusUserRequestor;
import be.atbash.ee.security.octopus.sso.core.OctopusRetrievalException;
import be.atbash.ee.security.octopus.sso.core.rest.DefaultPrincipalUserInfoJSONProvider;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOTokenConverter;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;

import java.net.URISyntaxException;

/**
 *
 */
public class ClientAuthenticationInfoProvider extends AuthenticationInfoProvider {

    private OctopusCoreConfiguration coreConfiguration;
    private OctopusSSOServerClientConfiguration configuration;

    private void init() {
        if (coreConfiguration == null) {
            coreConfiguration = OctopusCoreConfiguration.getInstance();
            configuration = OctopusSSOServerClientConfiguration.getInstance();
        }
    }

    @Override
    public AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        init();

        if (token instanceof UsernamePasswordToken) {
            // for the Java SE use case

            UsernamePasswordToken usernamePassword = (UsernamePasswordToken) token;
            TokenResponse tokenResponse = TokenRequestor.getInstance(coreConfiguration, configuration).getToken(usernamePassword);

            if (!tokenResponse.indicatesSuccess()) {
                TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
                // FIXME
                return null;
            }

            AccessTokenResponse accessTokenResponse = (AccessTokenResponse) tokenResponse;

            OctopusUserRequestor octopusUserRequestor = new OctopusUserRequestor(coreConfiguration, configuration, new OctopusSSOTokenConverter(),
                    new DefaultPrincipalUserInfoJSONProvider(), null);

            OpenIdVariableClientData clientData = new OpenIdVariableClientData();
            OctopusSSOToken octopusSSOToken;

            try {
                octopusSSOToken = octopusUserRequestor.getOctopusSSOToken(clientData, accessTokenResponse.getTokens().getBearerAccessToken());

            } catch (URISyntaxException | JOSEException | java.text.ParseException | OctopusRetrievalException | ParseException e) {
                e.printStackTrace(); // FIXME
                return null;
            }

            return new SSOAuthenticationInfoBuilder(octopusSSOToken).getAuthenticationInfo();
        }

        return null;
    }

    // FIXME Usage of PermissionRequestor to retrieve permissions.

    @Override
    public AuthenticationStrategy getAuthenticationStrategy() {
        return AuthenticationStrategy.SUFFICIENT;
    }
}
