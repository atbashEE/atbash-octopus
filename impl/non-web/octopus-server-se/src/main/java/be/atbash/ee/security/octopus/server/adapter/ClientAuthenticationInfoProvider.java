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
package be.atbash.ee.security.octopus.server.adapter;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.authc.AuthenticationInfoProvider;
import be.atbash.ee.security.octopus.authc.AuthenticationStrategy;
import be.atbash.ee.security.octopus.server.requestor.TokenRequestor;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenResponse;

import javax.enterprise.context.ApplicationScoped;


public class ClientAuthenticationInfoProvider extends AuthenticationInfoProvider {
    @Override
    protected AuthenticationInfo getAuthenticationInfo(AuthenticationToken token) {
        if (!(token instanceof UsernamePasswordToken)) {
            return null;  // FIXME Verify if this is ok for WEB
        }
        TokenResponse tokenResponse = TokenRequestor.getInstance().getToken((UsernamePasswordToken) token);

        if (!tokenResponse.indicatesSuccess()) {
            TokenErrorResponse errorResponse = (TokenErrorResponse) tokenResponse;
            System.out.println(errorResponse.getErrorObject());  // FIXME
            return null;
        }

        AccessTokenResponse accessTokenResponse = (AccessTokenResponse) tokenResponse;

        /*
        OctopusUserRequestor octopusUserRequestor = new OctopusUserRequestor(configuration, new OctopusSSOUserConverter(),
                new DefaultPrincipalUserInfoJSONProvider(), null);

        OpenIdVariableClientData clientData = new OpenIdVariableClientData();
        OctopusSSOUser octopusSSOUser = null;
        try {
            octopusSSOUser = octopusUserRequestor.getOctopusSSOUser(clientData, accessTokenResponse.getTokens().getBearerAccessToken());
            System.out.println(octopusSSOUser.getFullName());
            System.out.println(octopusSSOUser.getId());
            System.out.println(octopusSSOUser.getUserInfo());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        } catch (JOSEException e) {
            e.printStackTrace();
        } catch (java.text.ParseException e) {
            e.printStackTrace();
        } catch (OctopusRetrievalException e) {
            e.printStackTrace();
        }

        ClientConfig clientConfiguration = new ClientConfig();
        clientConfiguration.register(JacksonFeature.class);

        PermissionRequestor permissionRequestor = new PermissionRequestor(configuration, null, clientConfiguration, new PermissionJSONProvider());
        List<NamedDomainPermission> permissions = permissionRequestor.retrieveAllPermissions();
        System.out.println(permissions);

        permissions = permissionRequestor.retrieveUserPermissions(octopusSSOUser.getAccessToken());

        System.out.println(permissions);

         */
        return null;
    }

    @Override
    public AuthenticationStrategy getAuthenticationStrategy() {
        return AuthenticationStrategy.SUFFICIENT;
    }

}
