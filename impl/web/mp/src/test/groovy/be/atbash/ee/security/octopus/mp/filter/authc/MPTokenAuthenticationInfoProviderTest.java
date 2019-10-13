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
package be.atbash.ee.security.octopus.mp.filter.authc;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.mp.token.MPJWTToken;
import be.atbash.ee.security.octopus.mp.token.MPToken;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


public class MPTokenAuthenticationInfoProviderTest {

    private MPTokenAuthenticationInfoProvider provider = new MPTokenAuthenticationInfoProvider();

    @Test
    public void getAuthenticationInfo() {
        MPJWTToken jwtToken = new MPJWTToken();
        jwtToken.setSub("JUnit");
        jwtToken.setJti("Unique Id");
        MPToken token = new MPToken(jwtToken);

        AuthenticationInfo info = provider.getAuthenticationInfo(token);
        assertThat(info).isNotNull();
        UserPrincipal primaryPrincipal = info.getPrincipals().getPrimaryPrincipal();
        assertThat(primaryPrincipal.getUserName()).isEqualTo("JUnit");
        assertThat(primaryPrincipal.getName()).isEqualTo("JUnit");
        assertThat(primaryPrincipal.getId()).isEqualTo("Unique Id");
        Object infoToken = primaryPrincipal.getUserInfo("token");
        assertThat(infoToken).isNotNull();

    }

    @Test
    public void getAuthenticationInfo_autoId() {
        MPJWTToken jwtToken = new MPJWTToken();
        jwtToken.setSub("JUnit");
        MPToken token = new MPToken(jwtToken);

        AuthenticationInfo info = provider.getAuthenticationInfo(token);
        assertThat(info).isNotNull();
        UserPrincipal primaryPrincipal = info.getPrincipals().getPrimaryPrincipal();
        assertThat(primaryPrincipal.getUserName()).isEqualTo("JUnit");
        assertThat(primaryPrincipal.getName()).isEqualTo("JUnit");
        assertThat(primaryPrincipal.getId()).isNotNull();
        Object infoToken = primaryPrincipal.getUserInfo("token");
        assertThat(infoToken).isNotNull();

    }
}