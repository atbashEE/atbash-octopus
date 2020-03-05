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
package be.atbash.ee.security.octopus.sso;

import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.security.octopus.logout.LogoutParameters;
import be.atbash.ee.security.octopus.sso.client.logout.LogoutURLCreator;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;


@ExtendWith(MockitoExtension.class)
public class OctopusSSOLogoutURLProcessorTest {

    @Mock
    private LogoutURLCreator creatorMock;

    @InjectMocks
    private OctopusSSOLogoutURLProcessor processor;

    @Test
    public void postProcessLogoutUrl() {
        UserPrincipal userPrincipal = new UserPrincipal(1L, "junit", "JUnit");
        PrincipalCollection principalCollection = new PrincipalCollection(userPrincipal);
        OctopusSSOToken octopusSSOToken = new OctopusSSOToken();
        octopusSSOToken.setBearerAccessToken(new BearerAccessToken("theAccessCode"));
        principalCollection.add(octopusSSOToken);
        LogoutParameters parameters = new LogoutParameters(true, principalCollection);

        String logoutUrl = processor.postProcessLogoutUrl("http://server/logout", parameters);

        assertThat(logoutUrl).isNull();  // since mock is not programmed.
        verify(creatorMock).createLogoutURL("http://server/logout", "theAccessCode");
    }

    @Test
    public void postProcessLogoutUrl_noSingleLogout() {
        UserPrincipal userPrincipal = new UserPrincipal(1L, "junit", "JUnit");
        PrincipalCollection principalCollection = new PrincipalCollection(userPrincipal);

        LogoutParameters parameters = new LogoutParameters(false, principalCollection);

        String logoutUrl = processor.postProcessLogoutUrl("http://server/logout", parameters);

        assertThat(logoutUrl).isEqualTo("http://server/logout");
        verify(creatorMock, never()).createLogoutURL(anyString(), any(String.class));
    }

}