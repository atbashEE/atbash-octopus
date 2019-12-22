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
package be.atbash.ee.security.octopus.rememberme;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.config.RememberMeConfiguration;
import be.atbash.ee.security.octopus.crypto.AESCipherService;
import be.atbash.ee.security.octopus.realm.remember.DefaultSerializer;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.token.RememberMeAuthenticationToken;
import be.atbash.util.codec.ByteSource;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class CookieRememberMeManagerTest {

    @Mock
    private WebSubject webSubjectMock;

    @Mock
    private RememberMeAuthenticationToken tokenMock;

    @Mock
    private AuthenticationInfo infoMock;

    @Mock
    private RememberMeConfiguration rememberMeConfigurationMock;

    @Mock
    private HttpServletRequest servletRequestMock;

    @Mock
    private HttpServletResponse servletResponseMock;

    @InjectMocks
    private CookieRememberMeManager rememberMeManager;

    @Captor
    private ArgumentCaptor<Cookie> cookieArgumentCaptor;

    private byte[] encryptionKey;

    @Before
    public void setup() throws NoSuchAlgorithmException {
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        encryptionKey = key.getEncoded();
        when(rememberMeConfigurationMock.getCipherKey()).thenReturn(encryptionKey);

        rememberMeManager.init();
    }

    @Test
    public void onSuccessfulLogin_happyCase() {
        when(tokenMock.isRememberMe()).thenReturn(true);
        when(rememberMeConfigurationMock.getCookieName()).thenReturn("testCookie");
        when(webSubjectMock.getServletRequest()).thenReturn(servletRequestMock);
        when(webSubjectMock.getServletResponse()).thenReturn(servletResponseMock);

        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "Name");

        PrincipalCollection principals = new PrincipalCollection(userPrincipal);

        when(infoMock.getPrincipals()).thenReturn(principals);

        rememberMeManager.onSuccessfulLogin(webSubjectMock, tokenMock, infoMock);

        // 2 cookies, the first is the forget
        verify(servletResponseMock, times(2)).addCookie(cookieArgumentCaptor.capture());
        List<Cookie> cookies = cookieArgumentCaptor.getAllValues();
        Cookie cookie = cookies.get(1);
        assertThat(cookie.getName()).isEqualTo("testCookie");
        // Other tests are performed by AbstractRememberMeManagerTest

        // Check if the Cookie value is the Encrypted PrincipalCollection containing the UserPrincipal!
        byte[] rawBytes = Base64.getDecoder().decode(cookie.getValue().getBytes());
        AESCipherService cipherService = new AESCipherService();
        ByteSource decrypted = cipherService.decrypt(rawBytes, encryptionKey);

        DefaultSerializer serializer = new DefaultSerializer();
        PrincipalCollection principalCollection = serializer.deserialize(decrypted.getBytes());
        UserPrincipal primaryPrincipal = principalCollection.getPrimaryPrincipal();

        assertThat(primaryPrincipal).isEqualTo(userPrincipal);

    }
}