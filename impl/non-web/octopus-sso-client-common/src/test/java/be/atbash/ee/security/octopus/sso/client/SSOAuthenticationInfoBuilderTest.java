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
package be.atbash.ee.security.octopus.sso.client;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class SSOAuthenticationInfoBuilderTest {

    private SSOAuthenticationInfoBuilder builder;

    @Test
    public void getAuthenticationInfo() {
        OctopusSSOToken token = new OctopusSSOToken();
        token.setId("id");
        token.setUserName("userName");
        token.setFullName("fullName");
        token.setLocalId("localId");
        token.setEmail("email");

        token.addUserInfo("key", "value");
        builder = new SSOAuthenticationInfoBuilder(token);

        AuthenticationInfo info = builder.getAuthenticationInfo();

        assertThat(info).isNotNull();
        assertThat(info.isOneTimeAuthentication()).isTrue();

        assertThat(info.getPrincipals()).isNotNull();

        UserPrincipal primaryPrincipal = info.getPrincipals().getPrimaryPrincipal();
        assertThat(primaryPrincipal).isNotNull();

        assertThat(primaryPrincipal.getId()).isEqualTo("id");
        assertThat(primaryPrincipal.getUserName()).isEqualTo("userName");
        assertThat(primaryPrincipal.getName()).isEqualTo("fullName");
        assertThat(primaryPrincipal.getInfo()).containsKeys(OctopusConstants.EMAIL, OctopusConstants.LOCAL_ID, OctopusConstants.INFO_KEY_TOKEN, "key");

        OctopusSSOToken ssoToken = primaryPrincipal.getUserInfo(OctopusConstants.INFO_KEY_TOKEN);
        assertThat(ssoToken).isSameAs(token);

        assertThat(ssoToken.isLogoutHandlerNeeded()).isFalse();
    }

    @Test
    public void getAuthenticationInfo_withHandler() {
        OctopusSSOToken token = new OctopusSSOToken();
        token.setId("id");
        token.setUserName("userName");
        token.setFullName("fullName");
        token.setLocalId("localId");
        token.setEmail("email");

        token.addUserInfo("key", "value");
        token.setLogoutHandlerAsRequired();
        builder = new SSOAuthenticationInfoBuilder(token);

        AuthenticationInfo info = builder.getAuthenticationInfo();

        assertThat(info).isNotNull();
        assertThat(info.isOneTimeAuthentication()).isTrue();

        assertThat(info.getPrincipals()).isNotNull();

        UserPrincipal primaryPrincipal = info.getPrincipals().getPrimaryPrincipal();
        assertThat(primaryPrincipal).isNotNull();

        assertThat(primaryPrincipal.getId()).isEqualTo("id");
        assertThat(primaryPrincipal.getUserName()).isEqualTo("userName");
        assertThat(primaryPrincipal.getName()).isEqualTo("fullName");
        assertThat(primaryPrincipal.getInfo()).containsKeys(OctopusConstants.EMAIL, OctopusConstants.LOCAL_ID, OctopusConstants.INFO_KEY_TOKEN, "key");

        OctopusSSOToken ssoToken = primaryPrincipal.getUserInfo(OctopusConstants.INFO_KEY_TOKEN);
        assertThat(ssoToken).isSameAs(token);

        assertThat(ssoToken.isLogoutHandlerNeeded()).isTrue();
    }
}