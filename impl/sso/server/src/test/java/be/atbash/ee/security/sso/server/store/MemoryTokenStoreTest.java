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
package be.atbash.ee.security.sso.server.store;

import be.atbash.ee.security.octopus.subject.UserPrincipal;
import be.atbash.ee.security.octopus.util.TimeUtil;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.TestReflectionUtils;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class MemoryTokenStoreTest {
    private static final String ACCESS_TOKEN = "AccessToken";
    private static final String THE_COOKIE = "TheCookie";
    private static final String BROWSER = "Browser";
    private static final String LOCAL_HOST = "localHost";
    private static final String CLIENT_ID1 = "clientId1";
    private static final String CLIENT_ID2 = "clientId2";
    private static final String AUTHORIZATION_CODE = "authorizationCode";

    private MemoryTokenStore memoryTokenStore = new MemoryTokenStore();

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup()  {

        beanManagerFake = new BeanManagerFake();

        beanManagerFake.registerBean(new TimeUtil(), TimeUtil.class);

        beanManagerFake.endRegistration();
    }

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void addLoginFromClient_noAuthorization() throws NoSuchFieldException, IllegalAccessException {
        UserPrincipal userPrincipal = new UserPrincipal(1L, "junit", "JUnit Test");
        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(ACCESS_TOKEN));
        oidcStoreData.setClientId(new ClientID(CLIENT_ID1));
        memoryTokenStore.addLoginFromClient(userPrincipal, THE_COOKIE, BROWSER, LOCAL_HOST, oidcStoreData);

        Map<String, TokenStoreInfo> byAccessCode = TestReflectionUtils.getValueOf(memoryTokenStore, "byAccessCode");
        assertThat(byAccessCode).hasSize(1);
        assertThat(byAccessCode).containsOnlyKeys(ACCESS_TOKEN);
        assertThat(byAccessCode.get(ACCESS_TOKEN).getCookieToken()).isEqualTo(THE_COOKIE);
        assertThat(byAccessCode.get(ACCESS_TOKEN).getUserAgent()).isEqualTo(BROWSER);
        assertThat(byAccessCode.get(ACCESS_TOKEN).getRemoteHost()).isEqualTo(LOCAL_HOST);
        assertThat(byAccessCode.get(ACCESS_TOKEN).getUserPrincipal()).isSameAs(userPrincipal);
        // TODO The oidcdata issue

        Map<String, TokenStoreInfo> byCookie = TestReflectionUtils.getValueOf(memoryTokenStore, "byCookieCode");
        assertThat(byCookie).hasSize(1);
        assertThat(byCookie).containsOnlyKeys(THE_COOKIE);
        assertThat(byCookie.get(THE_COOKIE)).isSameAs(byAccessCode.get(ACCESS_TOKEN));

        Map<String, OIDCStoreData> byAuthorizationCode = TestReflectionUtils.getValueOf(memoryTokenStore, "byAuthorizationCode");
        assertThat(byAuthorizationCode).isEmpty();
    }

    @Test
    public void addLoginFromClient_Authorization() throws NoSuchFieldException {
        UserPrincipal userPrincipal = new UserPrincipal(1L, "junit", "JUnit Test");
        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(ACCESS_TOKEN));
        oidcStoreData.setClientId(new ClientID(CLIENT_ID1));
        oidcStoreData.setAuthorizationCode(new AuthorizationCode(AUTHORIZATION_CODE));
        memoryTokenStore.addLoginFromClient(userPrincipal, THE_COOKIE, BROWSER, LOCAL_HOST, oidcStoreData);

        Map<String, TokenStoreInfo> byAccessCode = TestReflectionUtils.getValueOf(memoryTokenStore, "byAccessCode");
        assertThat(byAccessCode).hasSize(1);
        assertThat(byAccessCode).containsOnlyKeys(ACCESS_TOKEN);
        assertThat(byAccessCode.get(ACCESS_TOKEN).getCookieToken()).isEqualTo(THE_COOKIE);
        assertThat(byAccessCode.get(ACCESS_TOKEN).getUserAgent()).isEqualTo(BROWSER);
        assertThat(byAccessCode.get(ACCESS_TOKEN).getRemoteHost()).isEqualTo(LOCAL_HOST);
        assertThat(byAccessCode.get(ACCESS_TOKEN).getUserPrincipal()).isSameAs(userPrincipal);
        // TODO The oidcdata issue

        Map<String, TokenStoreInfo> byCookie = TestReflectionUtils.getValueOf(memoryTokenStore, "byCookieCode");
        assertThat(byCookie).hasSize(1);
        assertThat(byCookie).containsOnlyKeys(THE_COOKIE);
        assertThat(byCookie.get(THE_COOKIE)).isSameAs(byAccessCode.get(ACCESS_TOKEN));

        Map<String, OIDCStoreData> byAuthorizationCode = TestReflectionUtils.getValueOf(memoryTokenStore, "byAuthorizationCode");
        assertThat(byAuthorizationCode).containsOnlyKeys(AUTHORIZATION_CODE);
        assertThat(byAuthorizationCode.get(AUTHORIZATION_CODE)).isSameAs(oidcStoreData);
    }


    @Test
    public void addLoginFromClient_noAuthorization_multipleLogin() {
        // TODO The oidcdata issue
    }

    @Test
    public void getUserByAccessCode() throws NoSuchFieldException {
        UserPrincipal userPrincipal = new UserPrincipal(1L, "junit", "JUnit Test");
        TokenStoreInfo tokenStoreInfo = new TokenStoreInfo(userPrincipal, THE_COOKIE, BROWSER, LOCAL_HOST);

        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(ACCESS_TOKEN, 10L, null));  // 10 Seconds to live
        tokenStoreInfo.addOIDCStoreData(oidcStoreData);

        Map<String, TokenStoreInfo> byAccessCode = new HashMap<>();
        byAccessCode.put(ACCESS_TOKEN, tokenStoreInfo);
        TestReflectionUtils.setFieldValue(memoryTokenStore, "byAccessCode", byAccessCode);

        UserPrincipal user = memoryTokenStore.getUserByAccessCode(ACCESS_TOKEN);
        assertThat(user).isSameAs(userPrincipal);
    }


    @Test
    public void getUserByAccessCode_expiredToken() throws NoSuchFieldException, InterruptedException {
        UserPrincipal userPrincipal = new UserPrincipal(1L, "junit", "JUnit Test");
        TokenStoreInfo tokenStoreInfo = new TokenStoreInfo(userPrincipal, THE_COOKIE, BROWSER, LOCAL_HOST);

        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(ACCESS_TOKEN, 2L, null));  // 2 Seconds to live
        tokenStoreInfo.addOIDCStoreData(oidcStoreData);

        Map<String, TokenStoreInfo> byAccessCode = new HashMap<String, TokenStoreInfo>();
        byAccessCode.put(ACCESS_TOKEN, tokenStoreInfo);
        TestReflectionUtils.setFieldValue(memoryTokenStore, "byAccessCode", byAccessCode);

        Thread.sleep(2500);  // By the end of this wait the token is expired

        UserPrincipal user = memoryTokenStore.getUserByAccessCode(ACCESS_TOKEN);
        assertThat(user).isNull();

        assertThat(byAccessCode).isEmpty();  // Removed the token
    }

    @Test
    public void getUserByAccessCode_NotFound() throws NoSuchFieldException {
        UserPrincipal userPrincipal = new UserPrincipal(1L, "junit", "JUnit Test");
        TokenStoreInfo tokenStoreInfo = new TokenStoreInfo(userPrincipal, THE_COOKIE, BROWSER, LOCAL_HOST);

        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken(10L, null));  // Random token
        tokenStoreInfo.addOIDCStoreData(oidcStoreData);


        Map<String, TokenStoreInfo> byAccessCode = new HashMap<String, TokenStoreInfo>();
        byAccessCode.put(ACCESS_TOKEN, tokenStoreInfo);
        TestReflectionUtils.setFieldValue(memoryTokenStore, "byAccessCode", byAccessCode);

        UserPrincipal user = memoryTokenStore.getUserByAccessCode("SomethingElse");
        assertThat(user).isNull();
    }

    @Test
    public void getOIDCDataByAuthorizationCode() throws NoSuchFieldException {
        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken());
        oidcStoreData.setClientId(new ClientID(CLIENT_ID1));
        oidcStoreData.setAuthorizationCode(new AuthorizationCode(AUTHORIZATION_CODE));


        Map<String, OIDCStoreData> byAuthorizationCode = new HashMap<String, OIDCStoreData>();
        byAuthorizationCode.put(AUTHORIZATION_CODE, oidcStoreData);

        TestReflectionUtils.setFieldValue(memoryTokenStore, "byAuthorizationCode", byAuthorizationCode);

        OIDCStoreData code = memoryTokenStore.getOIDCDataByAuthorizationCode(new AuthorizationCode(AUTHORIZATION_CODE), new ClientID(CLIENT_ID1));
        assertThat(code).isSameAs(oidcStoreData);

        assertThat(byAuthorizationCode).isEmpty(); // We have removed the entry !!

    }

    @Test
    public void getOIDCDataByAuthorizationCode_wrongClientId() throws NoSuchFieldException {
        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken());
        oidcStoreData.setClientId(new ClientID(CLIENT_ID1));
        oidcStoreData.setAuthorizationCode(new AuthorizationCode(AUTHORIZATION_CODE));


        Map<String, OIDCStoreData> byAuthorizationCode = new HashMap<>();
        byAuthorizationCode.put(AUTHORIZATION_CODE, oidcStoreData);

        TestReflectionUtils.setFieldValue(memoryTokenStore, "byAuthorizationCode", byAuthorizationCode);

        OIDCStoreData code = memoryTokenStore.getOIDCDataByAuthorizationCode(new AuthorizationCode(AUTHORIZATION_CODE), new ClientID(CLIENT_ID2));
        assertThat(code).isNull();

    }

    @Test
    public void getOIDCDataByAuthorizationCode_NotFound() throws NoSuchFieldException {
        OIDCStoreData oidcStoreData = new OIDCStoreData(new BearerAccessToken());
        oidcStoreData.setClientId(new ClientID(CLIENT_ID1));
        oidcStoreData.setAuthorizationCode(new AuthorizationCode(AUTHORIZATION_CODE));


        Map<String, OIDCStoreData> byAuthorizationCode = new HashMap<String, OIDCStoreData>();
        byAuthorizationCode.put(AUTHORIZATION_CODE, oidcStoreData);

        TestReflectionUtils.setFieldValue(memoryTokenStore, "byAuthorizationCode", byAuthorizationCode);

        OIDCStoreData code = memoryTokenStore.getOIDCDataByAuthorizationCode(new AuthorizationCode("SomeThingElse"), new ClientID(CLIENT_ID1));
        assertThat(code).isNull();

    }

}