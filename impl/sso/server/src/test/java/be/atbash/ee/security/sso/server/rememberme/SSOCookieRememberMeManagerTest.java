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
package be.atbash.ee.security.sso.server.rememberme;

import be.atbash.ee.security.octopus.WebConstants;
import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.config.RememberMeConfiguration;
import be.atbash.ee.security.octopus.crypto.AESCipherService;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.token.RememberMeAuthenticationToken;
import be.atbash.ee.security.sso.server.config.OctopusSSOServerConfiguration;
import be.atbash.ee.security.sso.server.cookie.SSOHelper;
import be.atbash.util.codec.ByteSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class SSOCookieRememberMeManagerTest {


    @Mock
    private WebSubject webSubjectMock;

    @Mock
    private RememberMeAuthenticationToken tokenMock;

    @Mock
    private AuthenticationInfo infoMock;

    @Mock
    private RememberMeConfiguration rememberMeConfigurationMock;

    @Mock
    private OctopusSSOServerConfiguration ssoServerConfigurationMock;


    @Mock
    private SSOHelper ssoHelperMock;

    @Mock
    private HttpServletRequest servletRequestMock;

    @Mock
    private HttpServletResponse servletResponseMock;

    @InjectMocks
    private SSOCookieRememberMeManager rememberMeManager;

    @Captor
    private ArgumentCaptor<Cookie> cookieArgumentCaptor;

    private byte[] encryptionKey;

    @BeforeEach
    public void setup() throws NoSuchAlgorithmException {
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        encryptionKey = key.getEncoded();
        when(rememberMeConfigurationMock.getCipherKey()).thenReturn(encryptionKey);

        rememberMeManager.init();
    }

    @Test
    public void onSuccessfulLogin_happyCase() {
        when(ssoServerConfigurationMock.getSSOCookieName()).thenReturn("testSSOCookie");
        when(webSubjectMock.getServletRequest()).thenReturn(servletRequestMock);
        when(webSubjectMock.getServletResponse()).thenReturn(servletResponseMock);

        when(ssoHelperMock.getSSOClientId(any(WebSubject.class))).thenReturn("clientId");

        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "Name");

        PrincipalCollection principals = new PrincipalCollection(userPrincipal);

        when(infoMock.getPrincipals()).thenReturn(principals);

        rememberMeManager.onSuccessfulLogin(webSubjectMock, tokenMock, infoMock);

        // Only 1 cookie here, no forget
        verify(servletResponseMock).addCookie(cookieArgumentCaptor.capture());

        Cookie cookie = cookieArgumentCaptor.getValue();
        assertThat(cookie.getName()).isEqualTo("testSSOCookie");

        // Check if the Cookie value is the Encrypted UUID
        byte[] rawBytes = Base64.getDecoder().decode(cookie.getValue().getBytes());
        AESCipherService cipherService = new AESCipherService();
        ByteSource decrypted = cipherService.decrypt(rawBytes, encryptionKey);

        String cookieToken = new String(decrypted.getBytes());
        UUID uuid = UUID.fromString(cookieToken);
        assertThat(uuid).isNotNull();

        String cookieTokenInfo = userPrincipal.getUserInfo(WebConstants.SSO_COOKIE_TOKEN);
        assertThat(cookieTokenInfo).isEqualTo(cookieToken);

    }
}