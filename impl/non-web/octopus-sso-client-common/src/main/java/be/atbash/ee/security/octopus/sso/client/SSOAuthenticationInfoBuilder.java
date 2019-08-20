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
package be.atbash.ee.security.octopus.sso.client;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.sso.client.logout.OctopusLogoutHandler;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.UserPrincipal;

/**
 *
 */
public class SSOAuthenticationInfoBuilder {

    private AuthenticationInfo authenticationInfo;

    public SSOAuthenticationInfoBuilder(OctopusSSOToken octopusSSOToken) {
        buildInfo(octopusSSOToken);
    }

    private void buildInfo(OctopusSSOToken octopusSSOToken) {

        UserPrincipal principal = new UserPrincipal(octopusSSOToken.getId(), octopusSSOToken.getUserName(), octopusSSOToken.getName());
        principal.addUserInfo(octopusSSOToken.getUserInfo());
        principal.addUserInfo(OctopusConstants.EMAIL, octopusSSOToken.getEmail());  // Make sure the email is within the userInfo
        principal.addUserInfo(OctopusConstants.LOCAL_ID, octopusSSOToken.getLocalId());

        if (octopusSSOToken.isLogoutHandlerNeeded()) {
            // In order for the logout with SSO Server.
            principal.setRemoteLogoutHandler(new OctopusLogoutHandler());
        }
        authenticationInfo = new AuthenticationInfo(principal, octopusSSOToken, true);

    }

    public AuthenticationInfo getAuthenticationInfo() {
        return authenticationInfo;
    }

}
