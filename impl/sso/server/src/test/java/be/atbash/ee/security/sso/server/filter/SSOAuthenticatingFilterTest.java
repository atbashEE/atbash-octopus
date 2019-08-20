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
package be.atbash.ee.security.sso.server.filter;

import be.atbash.ee.security.octopus.authc.IncorrectDataToken;
import be.atbash.ee.security.octopus.config.Debug;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOToken;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import be.atbash.ee.security.octopus.util.TimeUtil;
import be.atbash.ee.security.sso.server.store.OIDCStoreData;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.util.BeanManagerFake;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SSOAuthenticatingFilterTest {

    private static final String ACCESS_TOKEN = "realToken";

    @Mock
    private HttpServletRequest httpServletRequestMock;

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private SSOTokenStore tokenStore;

    @Mock
    private OctopusCoreConfiguration octopusCoreConfigurationMock;

    @InjectMocks
    private SSOAuthenticatingFilter ssoAuthenticatingFilter;


    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(octopusCoreConfigurationMock, OctopusCoreConfiguration.class);
        beanManagerFake.registerBean(new TimeUtil(), TimeUtil.class);
        beanManagerFake.endRegistration();

        when(octopusCoreConfigurationMock.showDebugFor()).thenReturn(new ArrayList<Debug>());
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void createToken_missingAuthenticationHeader() {
        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(IncorrectDataToken.class);
        IncorrectDataToken incorrect = (IncorrectDataToken) token;
        assertThat(incorrect.toString()).containsOnlyOnce("Authorization header required");
    }

    @Test
    public void createToken_IncorrectAuthorizationHeader() {
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("JUnit");

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(IncorrectDataToken.class);
        IncorrectDataToken incorrect = (IncorrectDataToken) token;
        assertThat(incorrect.toString()).containsOnlyOnce("Authorization header value incorrect");
    }

    @Test
    public void createToken_IncorrectAuthorizationHeader2() {
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Part1 Part2");

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(IncorrectDataToken.class);
        IncorrectDataToken incorrect = (IncorrectDataToken) token;
        assertThat(incorrect.toString()).containsOnlyOnce("Authorization header value must start with Bearer");
    }

    @Test
    public void createToken_tokenInvalid() {
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer token");

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(IncorrectDataToken.class);
        IncorrectDataToken incorrect = (IncorrectDataToken) token;
        assertThat(incorrect.toString()).containsOnlyOnce("Authentication failed");
    }

    @Test
    public void createToken_realTokenNotActive() {
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer token");

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(IncorrectDataToken.class);
        IncorrectDataToken incorrect = (IncorrectDataToken) token;
        assertThat(incorrect.toString()).containsOnlyOnce("Authentication failed");
    }

    @Test
    public void createToken() {
        when(httpServletRequestMock.getHeader("Authorization")).thenReturn("Bearer realToken");

        UserPrincipal user = new UserPrincipal("id", "junit", "JUnit Name");

        when(tokenStore.getUserByAccessCode(ACCESS_TOKEN)).thenReturn(user);
        OIDCStoreData oidcData = new OIDCStoreData(new BearerAccessToken(ACCESS_TOKEN));
        Scope scope = Scope.parse("openid octopus");
        oidcData.setScope(scope);
        when(tokenStore.getOIDCDataByAccessToken(ACCESS_TOKEN)).thenReturn(oidcData);

        AuthenticationToken token = ssoAuthenticatingFilter.createToken(httpServletRequestMock, httpServletResponseMock);

        assertThat(token).isInstanceOf(OctopusSSOToken.class);

        OctopusSSOToken ssoToken = (OctopusSSOToken) token;
        assertThat(ssoToken.getId()).isEqualTo("id");
        assertThat(ssoToken.getUserName()).isEqualTo("junit");

        verify(httpServletRequestMock).setAttribute(Scope.class.getName(), scope);
    }

}