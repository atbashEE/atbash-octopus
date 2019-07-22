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
package be.atbash.ee.security.octopus.realm.remember;

import be.atbash.ee.security.octopus.authc.AuthenticationInfo;
import be.atbash.ee.security.octopus.crypto.AESCipherService;
import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.SubjectContext;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.OTPToken;
import be.atbash.ee.security.octopus.token.RememberMeAuthenticationToken;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class AbstractRememberMeManagerTest {

    private TestRememberMeManager rememberMeManager = new TestRememberMeManager();

    @Mock
    private Subject subjectMock;

    @Mock
    private RememberMeAuthenticationToken tokenMock;

    @Mock
    private AuthenticationInfo infoMock;

    @Mock
    private SubjectContext subjectContextMock;

    @Test
    public void isRememberMe_remembered() {
        UsernamePasswordToken token = new UsernamePasswordToken("JUnit", "secret", true);
        assertThat(rememberMeManager.isRememberMe(token)).isTrue();
    }

    @Test
    public void isRememberMe_notRemembered() {
        UsernamePasswordToken token = new UsernamePasswordToken("JUnit", "secret", false);
        assertThat(rememberMeManager.isRememberMe(token)).isFalse();
    }

    @Test
    public void isRememberMe_wrongTokenType() {
        OTPToken token = new OTPToken("xyz");
        assertThat(rememberMeManager.isRememberMe(token)).isFalse();
    }

    @Test
    public void onSuccessfulLogin_happyCase() {
        when(tokenMock.isRememberMe()).thenReturn(true);

        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "Name");

        PrincipalCollection principals = new PrincipalCollection(userPrincipal);

        when(infoMock.getPrincipals()).thenReturn(principals);

        byte[] key = "secretKeyValueXY".getBytes();
        rememberMeManager.setCipherKey(key);
        rememberMeManager.onSuccessfulLogin(subjectMock, tokenMock, infoMock);

        assertThat(rememberMeManager.forgetCalled).isTrue();
        assertThat(rememberMeManager.rememberIdentityCalled).isTrue();

    }

    @Test
    public void onSuccessfulLogin_notRemembered() {
        when(tokenMock.isRememberMe()).thenReturn(false);
        rememberMeManager.onSuccessfulLogin(subjectMock, tokenMock, infoMock);

        assertThat(rememberMeManager.forgetCalled).isTrue();
        assertThat(rememberMeManager.rememberIdentityCalled).isFalse();

    }

    @Test
    public void getRememberedPrincipals_happyCase() {
        // Created an encrypted version of a UserPrincipal
        byte[] key = "secretKeyValueXY".getBytes();
        AESCipherService service = new AESCipherService();

        UserPrincipal userPrincipal = new UserPrincipal(1L, "JUnit", "Name");
        PrincipalCollection principals = new PrincipalCollection(userPrincipal);

        DefaultSerializer serializer = new DefaultSerializer();
        rememberMeManager.rememberedIdentity = service.encrypt(serializer.serialize(principals), key).getBytes();

        // Use the same key for the Service used by the RememberMeManager
        rememberMeManager.setCipherKey(key);

        PrincipalCollection principalCollection = rememberMeManager.getRememberedPrincipals(subjectContextMock);
        assertThat(principalCollection).hasSize(1);
        assertThat(principalCollection.getPrimaryPrincipal()).isEqualTo(userPrincipal);
    }


    @Test
    public void getRememberedPrincipals_noBytesForPrincipal() {
        rememberMeManager.rememberedIdentity = null;

        PrincipalCollection principalCollection = rememberMeManager.getRememberedPrincipals(subjectContextMock);
        assertThat(principalCollection).isNull();
    }

    public static class TestRememberMeManager extends AbstractRememberMeManager {

        private boolean forgetCalled;
        private boolean rememberIdentityCalled;
        private byte[] rememberedIdentity;

        @Override
        protected void forgetIdentity(Subject subject) {
            forgetCalled = true;
        }

        @Override
        protected void rememberSerializedIdentity(Subject subject, byte[] serialized) {
            this.rememberIdentityCalled = true;
        }

        @Override
        protected byte[] getRememberedSerializedIdentity(SubjectContext subjectContext) {
            return rememberedIdentity;
        }

        @Override
        public void forgetIdentity(SubjectContext subjectContext) {

        }
    }
}