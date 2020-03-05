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
package be.atbash.ee.security.sso.server.store;

import be.atbash.ee.oauth2.sdk.id.ClientID;
import be.atbash.ee.oauth2.sdk.token.BearerAccessToken;
import be.atbash.ee.security.octopus.util.TimeUtil;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class TokenStoreInfoTest {
    private static ClientID CLIENT_ID1;
    private static ClientID CLIENT_ID2;

    private TokenStoreInfo storeInfo;

    private BeanManagerFake beanManagerFake = new BeanManagerFake();

    @BeforeEach
    public void setup() {
        storeInfo = new TokenStoreInfo(null, null, null, null);

        CLIENT_ID1 = new ClientID("clientId1");
        CLIENT_ID2 = new ClientID("clientId2");

        beanManagerFake.registerBean(new TimeUtil(), TimeUtil.class);
        beanManagerFake.endRegistration();
    }

    @AfterEach
    public void destroy() {
        beanManagerFake.deregistration();
    }

    @Test
    public void addOIDCStoreData() {

        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID1));

        List<OIDCStoreData> oidcStoreData = storeInfo.getOidcStoreData();
        assertThat(oidcStoreData).hasSize(1);

    }

    @Test
    public void addOIDCStoreData_differentClientId() {

        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID1));
        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID2));

        List<OIDCStoreData> oidcStoreData = storeInfo.getOidcStoreData();
        assertThat(oidcStoreData).hasSize(2);

    }

    @Test
    public void addOIDCStoreData_sameClientId() {

        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID1));
        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID1));

        List<OIDCStoreData> oidcStoreData = storeInfo.getOidcStoreData();
        assertThat(oidcStoreData).hasSize(1);

    }

    @Test
    public void addOIDCStoreData_oneEmptyClientId() {

        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID1));
        storeInfo.addOIDCStoreData(createOIDCStoreData(null));

        List<OIDCStoreData> oidcStoreData = storeInfo.getOidcStoreData();
        assertThat(oidcStoreData).hasSize(2);

    }

    @Test
    public void addOIDCStoreData_allEmptyClientId() throws NoSuchFieldException, IllegalAccessException {

        storeInfo.addOIDCStoreData(createOIDCStoreData(null));
        storeInfo.addOIDCStoreData(createOIDCStoreData(null));

        List<OIDCStoreData> oidcStoreData = storeInfo.getOidcStoreData();
        assertThat(oidcStoreData).hasSize(1);

    }

    @Test
    public void _toString() throws NoSuchFieldException, IllegalAccessException {

        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID1));

        String info = storeInfo.toString();

        assertThat(info).contains("clientIds=clientId1");

    }

    @Test
    public void toString_multipleIds() throws NoSuchFieldException, IllegalAccessException {

        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID1));
        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID2));

        String info = storeInfo.toString();

        assertThat(info).contains("clientIds=clientId1, clientId2");

    }

    @Test
    public void toString_multipleIds2() throws NoSuchFieldException, IllegalAccessException {

        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID1));
        storeInfo.addOIDCStoreData(createOIDCStoreData(null));

        String info = storeInfo.toString();

        assertThat(info).contains("clientIds=null, clientId1");

    }

    @Test
    public void findOIDCStoreData() {

        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID1));
        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID2));

        OIDCStoreData storeData = storeInfo.findOIDCStoreData("clientId2");

        assertThat(storeData.getClientId()).isEqualTo(CLIENT_ID2);
    }


    @Test
    public void findOIDCStoreData_notFound() {

        storeInfo.addOIDCStoreData(createOIDCStoreData(CLIENT_ID1));

        OIDCStoreData storeData = storeInfo.findOIDCStoreData("clientId2");

        assertThat(storeData).isNull();
    }

    @Test
    public void findOIDCStoreData_noData() {


        OIDCStoreData storeData = storeInfo.findOIDCStoreData("clientId2");

        assertThat(storeData).isNull();
    }


    private OIDCStoreData createOIDCStoreData(ClientID clientId) {
        BearerAccessToken token;

        if (clientId != null) {
            token = new BearerAccessToken(clientId.getValue());
        } else {
            token = new BearerAccessToken();
        }

        OIDCStoreData storeData = new OIDCStoreData(token);
        storeData.setClientId(clientId);
        return storeData;
    }
}