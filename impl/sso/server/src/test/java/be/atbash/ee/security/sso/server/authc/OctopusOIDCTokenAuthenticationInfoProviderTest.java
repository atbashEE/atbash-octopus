/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.sso.server.authc;

import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.sso.server.token.OIDCEndpointToken;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class OctopusOIDCTokenAuthenticationInfoProviderTest {

    private OctopusOIDCTokenAuthenticationInfoProvider infoProvider = new OctopusOIDCTokenAuthenticationInfoProvider();

    @Test
    public void getAuthenticationInfo() {

        ClientID clientId = new ClientID("junit-client");
        AuthenticationToken token = new OIDCEndpointToken(clientId);
        AuthenticationInfo authenticationInfo = infoProvider.getAuthenticationInfo(token);

        UserPrincipal userPrincipal = authenticationInfo.getPrincipals().getPrimaryPrincipal();
        assertThat(userPrincipal).isNotNull();
        assertThat(userPrincipal.getId()).isEqualTo("junit-client");
        assertThat(userPrincipal.getUserName()).isEqualTo("junit-client");
    }
}