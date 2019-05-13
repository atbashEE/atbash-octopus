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
package be.atbash.ee.security.octopus.authc;

import be.atbash.ee.security.octopus.subject.PrincipalCollection;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.token.UsernamePasswordToken;
import be.atbash.ee.security.octopus.token.ValidatedAuthenticationToken;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.security.enterprise.credential.Credential;
import javax.security.enterprise.identitystore.CredentialValidationResult;
import javax.security.enterprise.identitystore.IdentityStoreHandler;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class AuthenticationInfoProviderAdapterTest {

    @Mock
    private IdentityStoreHandler identityStoreHandlerMock;

    @InjectMocks
    private AuthenticationInfoProviderAdapter adapter;

    @Test
    public void getAuthenticationInfo() {

        Set<String> groups = new HashSet<>();
        groups.add("group1");
        groups.add("group2");
        CredentialValidationResult validationResult = new CredentialValidationResult("JUnit Caller", groups);
        when(identityStoreHandlerMock.validate(any(Credential.class))).thenReturn(validationResult);

        UsernamePasswordToken token = new UsernamePasswordToken("JUnit", "pass");
        AuthenticationInfo info = adapter.getAuthenticationInfo(token);


        PrincipalCollection principalCollection = info.getPrincipals();
        UserPrincipal userPrincipal = principalCollection.getPrimaryPrincipal();
        assertThat(userPrincipal.getUserName()).isEqualTo("JUnit");
        assertThat(userPrincipal.getId()).isEqualTo("JUnit");
        assertThat(userPrincipal.getName()).isEqualTo("JUnit Caller");
        assertThat(userPrincipal.getInfo()).containsOnlyKeys("token");

        Object credentials = info.getCredentials();
        assertThat(credentials).isNull();

        boolean oneTimeAuthentication = info.isOneTimeAuthentication();
        assertThat(oneTimeAuthentication).isFalse();

        ValidatedAuthenticationToken validatedToken = info.getValidatedToken();
        assertThat(validatedToken).isInstanceOf(CredentialValidationResultToken.class);

        CredentialValidationResultToken credentialValidationResultToken = (CredentialValidationResultToken) validatedToken;

        assertThat(credentialValidationResultToken.getCallerGroups()).containsOnly("group1", "group2");
    }

    @Test
    public void getAuthenticationInfo_supplyCallerId() {

        Set<String> groups = new HashSet<>();
        groups.add("group1");
        groups.add("group2");
        CredentialValidationResult validationResult = new CredentialValidationResult("storeId", "JUnit Caller", "DN", "Id", groups);
        when(identityStoreHandlerMock.validate(any(Credential.class))).thenReturn(validationResult);

        UsernamePasswordToken token = new UsernamePasswordToken("JUnit", "pass");
        AuthenticationInfo info = adapter.getAuthenticationInfo(token);

        PrincipalCollection principalCollection = info.getPrincipals();
        UserPrincipal userPrincipal = principalCollection.getPrimaryPrincipal();
        assertThat(userPrincipal.getUserName()).isEqualTo("JUnit");
        assertThat(userPrincipal.getId()).isEqualTo("Id");
        assertThat(userPrincipal.getName()).isEqualTo("JUnit Caller");
        assertThat(userPrincipal.getInfo()).containsOnlyKeys("token");

        Object credentials = info.getCredentials();
        assertThat(credentials).isNull();

        boolean oneTimeAuthentication = info.isOneTimeAuthentication();
        assertThat(oneTimeAuthentication).isFalse();

        ValidatedAuthenticationToken validatedToken = info.getValidatedToken();
        assertThat(validatedToken).isInstanceOf(CredentialValidationResultToken.class);

        CredentialValidationResultToken credentialValidationResultToken = (CredentialValidationResultToken) validatedToken;

        assertThat(credentialValidationResultToken.getCallerGroups()).containsOnly("group1", "group2");
    }

    @Test
    public void getAuthenticationInfo_Failed() {

        when(identityStoreHandlerMock.validate(any(Credential.class))).thenReturn(CredentialValidationResult.INVALID_RESULT);

        UsernamePasswordToken token = new UsernamePasswordToken("JUnit", "pass");
        AuthenticationInfo info = adapter.getAuthenticationInfo(token);

        assertThat(info).isNull();

    }

    @Test
    public void getAuthenticationInfo_NoUserNamlePassword() {

        AuthenticationInfo info = adapter.getAuthenticationInfo(new IncorrectDataToken("Test"));

        assertThat(info).isNull();

    }
}