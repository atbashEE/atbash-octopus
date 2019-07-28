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
package be.atbash.ee.security.sso.server.endpoint;

import be.atbash.ee.security.octopus.OctopusConstants;
import be.atbash.ee.security.octopus.config.OctopusCoreConfiguration;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.sso.core.config.OctopusSSOConfiguration;
import be.atbash.ee.security.octopus.sso.core.rest.PrincipalUserInfoJSONProvider;
import be.atbash.ee.security.octopus.sso.core.token.OctopusSSOTokenConverter;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.ee.security.octopus.util.SecretUtil;
import be.atbash.ee.security.sso.server.TimeUtil;
import be.atbash.ee.security.sso.server.client.ClientInfo;
import be.atbash.ee.security.sso.server.client.ClientInfoRetriever;
import be.atbash.ee.security.sso.server.config.OctopusSSOServerConfiguration;
import be.atbash.ee.security.sso.server.config.UserEndpointEncoding;
import be.atbash.ee.security.sso.server.store.OIDCStoreData;
import be.atbash.ee.security.sso.server.store.SSOTokenStore;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.TestReflectionUtils;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Audience;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import net.minidev.json.parser.JSONParser;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class OctopusSSOEndpointTest {

    private static final String CLIENT_ID = "JUnit client";

    @Mock
    private OctopusCoreConfiguration octopusCoreConfigurationMock;

    @Mock
    private OctopusSSOServerConfiguration ssoServerConfigurationMock;

    @Mock
    private SSOPermissionProvider ssoPermissionProviderMock;

    @Mock
    private SSOTokenStore tokenStoreMock;

    @Mock
    private ClientInfoRetriever clientInfoRetrieverMock;

    @Mock
    private PrincipalUserInfoJSONProvider userInfoJSONProviderMock;

    @Mock
    private UserEndpointDataTransformer userEndpointDataTransformerMock;

    @Mock
    private WebSubject webSubjectMock;

    @InjectMocks
    private OctopusSSOEndpoint octopusSSOEndpoint;

    @Mock
    private UriInfo uriDetailsMock;

    @Mock
    private OctopusSSOConfiguration octopusSSOConfigurationMock;

    private BeanManagerFake beanManagerFake;

    private SecretUtil secretUtil;

    @Before
    public void setup() throws IllegalAccessException {
        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(new TimeUtil(), TimeUtil.class);

        octopusSSOEndpoint.init();
        when(ssoServerConfigurationMock.getUserEndpointEncoding()).thenReturn(UserEndpointEncoding.NONE);

        OctopusSSOTokenConverter converter = new OctopusSSOTokenConverter();
        TestReflectionUtils.injectDependencies(converter, octopusSSOConfigurationMock);

        TestReflectionUtils.injectDependencies(octopusSSOEndpoint, converter, new TimeUtil());

        secretUtil = new SecretUtil();
        secretUtil.init();
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void getUserInfo_octopusScope() throws URISyntaxException, ParseException {
        beanManagerFake.endRegistration();

        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(0, Scope.parse("openid octopus")));

        List<Audience> audience = new ArrayList<>();

        audience.add(new Audience(CLIENT_ID));
        IDTokenClaimsSet idTokenClaimSet = new IDTokenClaimsSet(new Issuer("tokenIssuer"), new Subject("JUnit"), audience, new Date(), new Date());
        oidcStoreData.setIdTokenClaimsSet(idTokenClaimSet);
        oidcStoreData.setClientId(new ClientID(CLIENT_ID));

        when(tokenStoreMock.getOIDCDataByAccessToken("accessToken")).thenReturn(oidcStoreData);

        ThreadContext.bind(webSubjectMock);
        UserPrincipal userPrincipal = new UserPrincipal("ssoUser-id", "username", "JUnit Test");
        when(webSubjectMock.getPrincipal()).thenReturn(userPrincipal);

        userPrincipal.addUserInfo(OctopusConstants.LOCAL_ID, "ssoUser-localId");
        userPrincipal.addUserInfo(OctopusConstants.FIRST_NAME, "JUnit");
        userPrincipal.addUserInfo(OctopusConstants.LAST_NAME, "Test");
        userPrincipal.addUserInfo("Extra Key", "The value");

        when(uriDetailsMock.getRequestUri()).thenReturn(new URI("http://some.server/oidc/octopus/sso/user"));
        when(octopusSSOConfigurationMock.getKeysToFilter()).thenReturn("");

        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setIdTokenSecret(secretUtil.generateSecretBase64(48));
        when(clientInfoRetrieverMock.retrieveInfo(CLIENT_ID)).thenReturn(clientInfo);

        String authorizationHeader = "Bearer accessToken";

        Response response = octopusSSOEndpoint.getUserInfo(authorizationHeader, uriDetailsMock);

        String data = response.getEntity().toString();
        assertThat(data).startsWith("ey");

        SignedJWT jwt = SignedJWT.parse(data);
        assertThat(jwt.getJWTClaimsSet().getClaims().keySet()).containsOnly("sub", "iss", "name", "id", "exp", "firstName", "localId", "iat", "lastName", "Extra Key", "aud", "preferred_username", "given_name", "family_name");
    }

    @Test
    public void getUserInfo_defaultScope() throws net.minidev.json.parser.ParseException {
        beanManagerFake.endRegistration();

        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(0, Scope.parse("openid")));

        ThreadContext.bind(webSubjectMock);
        UserPrincipal userPrincipal = new UserPrincipal();
        when(webSubjectMock.getPrincipal()).thenReturn(userPrincipal);

        List<Audience> audience = new ArrayList<>();

        audience.add(new Audience(CLIENT_ID));
        IDTokenClaimsSet idTokenClaimSet = new IDTokenClaimsSet(new Issuer("tokenIssuer"), new Subject("JUnit"), audience, new Date(), new Date());
        oidcStoreData.setIdTokenClaimsSet(idTokenClaimSet);
        oidcStoreData.setClientId(new ClientID(CLIENT_ID));

        when(tokenStoreMock.getOIDCDataByAccessToken("accessToken")).thenReturn(oidcStoreData);

        String authorizationHeader = "Bearer accessToken";

        Response response = octopusSSOEndpoint.getUserInfo(authorizationHeader, uriDetailsMock);

        String data = response.getEntity().toString();
        assertThat(data).startsWith("{");

        JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);
        JSONObject jsonObject = (JSONObject) parser.parse(data);

        assertThat(jsonObject.keySet()).containsOnly("sub", "iss", "aud", "exp", "iat");

        verifyZeroInteractions(clientInfoRetrieverMock);

    }

    @Test
    public void getUserInfo_customScope() throws net.minidev.json.parser.ParseException {
        when(userEndpointDataTransformerMock.transform(any(UserInfo.class), any(UserPrincipal.class), any(Scope.class))).thenAnswer(new Answer<UserInfo>() {
            @Override
            public UserInfo answer(InvocationOnMock invocation) throws Throwable {
                Scope scope = invocation.getArgument(2);
                if (scope.contains("JUnitScope")) {
                    UserInfo userInfo = invocation.getArgument(0);
                    userInfo.setClaim("JUnitClaim", "claimValue");
                    return userInfo;
                } else {
                    return invocation.getArgument(0);
                }
            }
        });

        beanManagerFake.registerBean(userEndpointDataTransformerMock, UserEndpointDataTransformer.class);
        beanManagerFake.endRegistration();

        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(0, Scope.parse("openid JUnitScope")));

        List<Audience> audience = new ArrayList<>();

        audience.add(new Audience(CLIENT_ID));
        IDTokenClaimsSet idTokenClaimSet = new IDTokenClaimsSet(new Issuer("tokenIssuer"), new Subject("JUnit"), audience, new Date(), new Date());
        oidcStoreData.setIdTokenClaimsSet(idTokenClaimSet);
        oidcStoreData.setClientId(new ClientID(CLIENT_ID));

        when(tokenStoreMock.getOIDCDataByAccessToken("accessToken")).thenReturn(oidcStoreData);

        String authorizationHeader = "Bearer accessToken";

        octopusSSOEndpoint.init();

        Response response = octopusSSOEndpoint.getUserInfo(authorizationHeader, uriDetailsMock);

        String data = response.getEntity().toString();
        assertThat(data).startsWith("{");

        JSONParser parser = new JSONParser(JSONParser.MODE_PERMISSIVE);
        JSONObject jsonObject = (JSONObject) parser.parse(data);

        assertThat(jsonObject.keySet()).containsOnly("sub", "iss", "aud", "exp", "iat", "JUnitClaim");

        verifyZeroInteractions(clientInfoRetrieverMock);

    }

}