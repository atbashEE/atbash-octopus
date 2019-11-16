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
package be.atbash.ee.security.octopus.sso.core.token;

import be.atbash.ee.openid.connect.sdk.claims.UserInfo;
import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.authz.permission.DomainPermission;
import be.atbash.ee.security.octopus.nimbus.util.JSONObjectUtils;
import be.atbash.ee.security.octopus.sso.core.config.OctopusSSOConfiguration;
import be.atbash.ee.security.octopus.sso.core.rest.PrincipalUserInfoJSONProvider;
import be.atbash.ee.security.octopus.sso.core.token.testclasses.WithDefaultConstructor;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.util.TestReflectionUtils;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

import javax.json.Json;
import javax.json.JsonObjectBuilder;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class OctopusSSOTokenConverterTest {

    @Mock
    private PrincipalUserInfoJSONProvider jsonProviderMock;

    @Mock
    private OctopusSSOConfiguration octopusSSOConfigurationMock;

    @InjectMocks
    private OctopusSSOTokenConverter octopusSSOUserConverter;

    @After
    public void clearLoggers() {
        TestLoggerFactory.clear();
    }

    @Test
    public void asClaims() {
        UserPrincipal userPrincipal = new UserPrincipal("IdValue", "UserNameValue", "FullNameValue");

        userPrincipal.addUserInfo(OctopusConstants.LOCAL_ID, "LocalIdValue");
        userPrincipal.addUserInfo(OctopusConstants.LAST_NAME, "LastNameValue");
        userPrincipal.addUserInfo(OctopusConstants.FIRST_NAME, "FirstNameValue");
        userPrincipal.addUserInfo(OctopusConstants.EMAIL, "EmailValue");

        userPrincipal.addUserInfo("token", "ShouldBeRemovedToken");
        userPrincipal.addUserInfo("upstreamToken", "ShouldBeRemovedUpstreamToken");
        userPrincipal.addUserInfo(OctopusConstants.AUTHORIZATION_INFO, "ShouldBeRemovedAuthorizationInfo");

        userPrincipal.addUserInfo("stringProperty", "StringPropertyValue");
        userPrincipal.addUserInfo("longProperty", 123L);
        userPrincipal.addUserInfo("booleanProperty", Boolean.TRUE);
        Date dateValue = new Date();
        userPrincipal.addUserInfo("dateProperty", dateValue);
        ArrayList<String> stringList = new ArrayList<>();
        stringList.add("JUnit");
        userPrincipal.addUserInfo("listProperty", stringList);

        // Just need a complex object. Nothing realistic here.
        DomainPermission permission = new DomainPermission();
        userPrincipal.addUserInfo("permission", permission);
        when(jsonProviderMock.writeValue(permission)).thenReturn("permissionSerialization");

        when(octopusSSOConfigurationMock.getKeysToFilter()).thenReturn("");

        Map<String, Object> claims = octopusSSOUserConverter.asClaims(userPrincipal, jsonProviderMock);

        assertThat(claims).containsEntry("id", "IdValue");
        assertThat(claims).containsEntry(OctopusConstants.LOCAL_ID, "LocalIdValue");

        assertThat(claims).containsEntry(UserInfo.PREFERRED_USERNAME_CLAIM_NAME, "UserNameValue");

        assertThat(claims).containsEntry(UserInfo.FAMILY_NAME_CLAIM_NAME, "LastNameValue");
        assertThat(claims).containsEntry(UserInfo.GIVEN_NAME_CLAIM_NAME, "FirstNameValue");
        assertThat(claims).containsEntry(UserInfo.NAME_CLAIM_NAME, "FullNameValue");
        assertThat(claims).containsEntry(UserInfo.EMAIL_CLAIM_NAME, "EmailValue");

        assertThat(claims).containsEntry("stringProperty", "StringPropertyValue");
        assertThat(claims).containsEntry("longProperty", 123L);
        assertThat(claims).containsEntry("booleanProperty", Boolean.TRUE);
        assertThat(claims).containsEntry("dateProperty", dateValue);
        assertThat(claims).containsEntry("listProperty", stringList);
        assertThat(claims).containsEntry("permission", "be.atbash.ee.security.octopus.authz.permission.DomainPermission@@permissionSerialization");

        assertThat(claims).doesNotContainKeys(OctopusConstants.TOKEN, OctopusConstants.UPSTREAM_TOKEN, OctopusConstants.AUTHORIZATION_INFO);
    }

    @Test
    public void asClaims_filtered() {
        UserPrincipal userPrincipal = new UserPrincipal("IdValue", "UserNameValue", "FullNameValue");

        userPrincipal.addUserInfo(OctopusConstants.LOCAL_ID, "LocalIdValue");
        userPrincipal.addUserInfo(OctopusConstants.LAST_NAME, "LastNameValue");
        userPrincipal.addUserInfo(OctopusConstants.FIRST_NAME, "FirstNameValue");
        userPrincipal.addUserInfo(OctopusConstants.EMAIL, "EmailValue");

        userPrincipal.addUserInfo("token", "ShouldBeRemovedToken");
        userPrincipal.addUserInfo("upstreamToken", "ShouldBeRemovedUpstreamToken");
        userPrincipal.addUserInfo(OctopusConstants.AUTHORIZATION_INFO, "ShouldBeRemovedAuthorizationInfo");

        userPrincipal.addUserInfo("stringProperty", "StringPropertyValue");

        when(octopusSSOConfigurationMock.getKeysToFilter()).thenReturn(" stringProperty , somethingElse");

        Map<String, Object> claims = octopusSSOUserConverter.asClaims(userPrincipal, jsonProviderMock);

        assertThat(claims).containsEntry("id", "IdValue");
        assertThat(claims).containsEntry(OctopusConstants.LOCAL_ID, "LocalIdValue");

        assertThat(claims).containsEntry(UserInfo.PREFERRED_USERNAME_CLAIM_NAME, "UserNameValue");

        assertThat(claims).containsEntry(UserInfo.FAMILY_NAME_CLAIM_NAME, "LastNameValue");
        assertThat(claims).containsEntry(UserInfo.GIVEN_NAME_CLAIM_NAME, "FirstNameValue");
        assertThat(claims).containsEntry(UserInfo.NAME_CLAIM_NAME, "FullNameValue");
        assertThat(claims).containsEntry(UserInfo.EMAIL_CLAIM_NAME, "EmailValue");

        assertThat(claims).doesNotContainKeys("stringProperty");
        assertThat(claims).doesNotContainKeys("token", "upstreamToken", OctopusConstants.AUTHORIZATION_INFO);
    }

    @Test
    public void fromUserInfo() {

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();

        jsonObject.add("id", "IdValue");
        jsonObject.add(OctopusConstants.LOCAL_ID, "LocalIdValue");

        jsonObject.add(UserInfo.PREFERRED_USERNAME_CLAIM_NAME, "UserNameValue");

        jsonObject.add(UserInfo.FAMILY_NAME_CLAIM_NAME, "LastNameValue");
        jsonObject.add(UserInfo.GIVEN_NAME_CLAIM_NAME, "FirstNameValue");
        jsonObject.add(UserInfo.NAME_CLAIM_NAME, "FullNameValue");
        jsonObject.add(UserInfo.EMAIL_CLAIM_NAME, "john.doe@acme.com");

        jsonObject.add("stringProperty", "StringPropertyValue");
        jsonObject.add("longProperty", 123L);
        jsonObject.add("booleanProperty", Boolean.TRUE);
        Date dateValue = new Date();
        jsonObject.add("dateProperty", dateValue.getTime());

        List<String> stringList = new ArrayList<>();
        stringList.add("JUnit");

        jsonObject.add("listProperty", JSONObjectUtils.asJsonArray(stringList));
        jsonObject.add("permission", "be.atbash.ee.security.octopus.authz.permission.DomainPermission@@permissionSerialization");

        jsonObject.add("sub", "RequiredByOpenIDConnectSpec");
        UserInfo userInfo = new UserInfo(jsonObject.build());

        DomainPermission permission = new DomainPermission();
        when(jsonProviderMock.readValue("permissionSerialization", DomainPermission.class)).thenReturn(permission);

        OctopusSSOToken ssoToken = octopusSSOUserConverter.fromUserInfo(userInfo, jsonProviderMock);

        assertThat(ssoToken.getId()).isEqualTo("IdValue");
        assertThat(ssoToken.getLocalId()).isEqualTo("LocalIdValue");

        assertThat(ssoToken.getUserName()).isEqualTo("UserNameValue");

        assertThat(ssoToken.getLastName()).isEqualTo("LastNameValue");
        assertThat(ssoToken.getFirstName()).isEqualTo("FirstNameValue");
        assertThat(ssoToken.getFullName()).isEqualTo("FullNameValue");
        assertThat(ssoToken.getEmail()).isEqualTo("john.doe@acme.com");

        assertThat(ssoToken.getUserInfo()).containsEntry("stringProperty", "StringPropertyValue");
        assertThat(ssoToken.getUserInfo()).containsEntry("longProperty", "123");
        assertThat(ssoToken.getUserInfo()).containsEntry("booleanProperty", "true");
        assertThat(ssoToken.getUserInfo()).containsEntry("dateProperty", String.valueOf(dateValue.getTime()));
        assertThat(ssoToken.getUserInfo()).containsEntry("listProperty", "[JUnit]");
        assertThat(ssoToken.getUserInfo()).containsEntry("permission", permission);

    }

    @Test
    public void fromUserInfo_noId() {

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add(OctopusConstants.LOCAL_ID, "LocalIdValue");

        jsonObject.add(UserInfo.PREFERRED_USERNAME_CLAIM_NAME, "UserNameValue");

        jsonObject.add("sub", "RequiredByOpenIDConnectSpec");
        UserInfo userInfo = new UserInfo(jsonObject.build());

        OctopusSSOToken ssoToken = octopusSSOUserConverter.fromUserInfo(userInfo, jsonProviderMock);

        assertThat(ssoToken.getId()).isEqualTo("UserNameValue");
        assertThat(ssoToken.getLocalId()).isEqualTo("LocalIdValue");

        assertThat(ssoToken.getUserName()).isEqualTo("UserNameValue");

    }

    @Test
    public void fromUserInfo_ForCredentialOwner() {

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add("id", "IdValue");
        jsonObject.add(OctopusConstants.LOCAL_ID, "LocalIdValue");

        jsonObject.add("sub", "RequiredByOpenIDConnectSpec");
        UserInfo userInfo = new UserInfo(jsonObject.build());

        OctopusSSOToken ssoToken = octopusSSOUserConverter.fromUserInfo(userInfo, jsonProviderMock);

        assertThat(ssoToken.getId()).isEqualTo("IdValue");
        assertThat(ssoToken.getLocalId()).isEqualTo("LocalIdValue");

        assertThat(ssoToken.getUserName()).isEqualTo("RequiredByOpenIDConnectSpec");

    }

    @Test
    public void fromUserInfo_EmailSupport() {
        // Fixing issue #136

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add("id", "IdValue");
        jsonObject.add(OctopusConstants.LOCAL_ID, "LocalIdValue");

        jsonObject.add("sub", "RequiredByOpenIDConnectSpec");
        jsonObject.add("mail", "some.person@foor.org");
        UserInfo userInfo = new UserInfo(jsonObject.build());

        OctopusSSOToken ssoToken = octopusSSOUserConverter.fromUserInfo(userInfo, jsonProviderMock);

        assertThat(ssoToken.getId()).isEqualTo("IdValue");
        assertThat(ssoToken.getLocalId()).isEqualTo("LocalIdValue");

        assertThat(ssoToken.getUserName()).isEqualTo("RequiredByOpenIDConnectSpec");
        assertThat(ssoToken.getUserInfo().get("mail")).isEqualTo("some.person@foor.org");

    }

    @Test
    public void fromUserInfo_UnknownClass() throws IllegalAccessException {
        // Fixing issue #137
        TestLogger logger = TestLoggerFactory.getTestLogger(OctopusSSOTokenConverter.class);
        TestReflectionUtils.injectDependencies(octopusSSOUserConverter, logger);

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add("id", "IdValue");
        jsonObject.add(OctopusConstants.LOCAL_ID, "LocalIdValue");

        jsonObject.add("sub", "RequiredByOpenIDConnectSpec");
        jsonObject.add("customKey", "be.atbash.security.demo.ServerClass@@{property=value}");
        UserInfo userInfo = new UserInfo(jsonObject.build());

        OctopusSSOToken ssoToken = octopusSSOUserConverter.fromUserInfo(userInfo, jsonProviderMock);

        assertThat(ssoToken.getId()).isEqualTo("IdValue");
        assertThat(ssoToken.getLocalId()).isEqualTo("LocalIdValue");

        assertThat(ssoToken.getUserName()).isEqualTo("RequiredByOpenIDConnectSpec");

        assertThat(ssoToken.getUserInfo().get("customKey")).isEqualTo("be.atbash.security.demo.ServerClass@@{property=value}");


        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Reading serialized userInfo data failed for OctopusSSOToken as class be.atbash.security.demo.ServerClass can't be located");

    }

    @Test
    public void fromUserInfo_NoDefaultConstructor() throws IllegalAccessException {
        TestLogger logger = TestLoggerFactory.getTestLogger(OctopusSSOTokenConverter.class);
        TestReflectionUtils.injectDependencies(octopusSSOUserConverter, logger);

        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add("id", "IdValue");
        jsonObject.add(OctopusConstants.LOCAL_ID, "LocalIdValue");

        jsonObject.add("sub", "RequiredByOpenIDConnectSpec");

        jsonObject.add("noDefaultConstructor", "be.atbash.ee.security.octopus.sso.core.token.testclasses.NoDefaultConstructor@@JUnit");
        UserInfo userInfo = new UserInfo(jsonObject.build());

        OctopusSSOToken ssoToken = octopusSSOUserConverter.fromUserInfo(userInfo, jsonProviderMock);

        assertThat(ssoToken.getId()).isEqualTo("IdValue");
        assertThat(ssoToken.getLocalId()).isEqualTo("LocalIdValue");

        assertThat(ssoToken.getUserInfo()).containsEntry("noDefaultConstructor", "be.atbash.ee.security.octopus.sso.core.token.testclasses.NoDefaultConstructor@@JUnit");

        assertThat(logger.getLoggingEvents()).hasSize(1);
        assertThat(logger.getLoggingEvents().get(0).getLevel()).isEqualTo(Level.WARN);
        assertThat(logger.getLoggingEvents().get(0).getMessage()).isEqualTo("Reading serialized userInfo data failed for OctopusSSOToken as class be.atbash.ee.security.octopus.sso.core.token.testclasses.NoDefaultConstructor doesn't have a default constructor");

        verify(jsonProviderMock, never()).readValue(anyString(), any(Class.class));
    }

    @Test
    public void fromUserInfo_WithDefaultConstructor() throws IllegalAccessException {
        JsonObjectBuilder jsonObject = Json.createObjectBuilder();
        jsonObject.add("id", "IdValue");
        jsonObject.add(OctopusConstants.LOCAL_ID, "LocalIdValue");

        jsonObject.add("sub", "RequiredByOpenIDConnectSpec");

        jsonObject.add("withDefaultConstructor", "be.atbash.ee.security.octopus.sso.core.token.testclasses.WithDefaultConstructor@@JUnit");
        UserInfo userInfo = new UserInfo(jsonObject.build());

        when(jsonProviderMock.readValue("JUnit", WithDefaultConstructor.class)).thenReturn(new WithDefaultConstructor("JUnit"));

        OctopusSSOToken ssoToken = octopusSSOUserConverter.fromUserInfo(userInfo, jsonProviderMock);

        assertThat(ssoToken.getId()).isEqualTo("IdValue");
        assertThat(ssoToken.getLocalId()).isEqualTo("LocalIdValue");

        assertThat(ssoToken.getUserInfo()).containsKey("withDefaultConstructor");
        WithDefaultConstructor data = ssoToken.getUserInfo("withDefaultConstructor");
        assertThat(data.getFoo()).isEqualTo("JUnit");

    }
}