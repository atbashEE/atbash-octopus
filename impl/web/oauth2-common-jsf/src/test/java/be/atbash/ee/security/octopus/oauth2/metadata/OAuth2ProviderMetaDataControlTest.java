/*
 * Copyright 2014-2018 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus.oauth2.metadata;

import be.atbash.util.BeanManagerFake;
import be.atbash.util.exception.AtbashIllegalActionException;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.junit.After;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */

public class OAuth2ProviderMetaDataControlTest {

    private BeanManagerFake beanManagerFake = new BeanManagerFake();

    private OAuth2ProviderMetaDataControl metaDataControl = new OAuth2ProviderMetaDataControl();

    private OAuth2ProviderMetaData providerMetaDataMock1 = Mockito.mock(OAuth2ProviderMetaData.class);
    private OAuth2ProviderMetaData providerMetaDataMock2 = Mockito.mock(OAuth2ProviderMetaData.class);

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void getProviderInfos() {
        beanManagerFake.registerBean(providerMetaDataMock1, OAuth2ProviderMetaData.class);
        beanManagerFake.registerBean(providerMetaDataMock2, OAuth2ProviderMetaData.class);
        beanManagerFake.endRegistration();
        metaDataControl.init();

        List<OAuth2ProviderMetaData> infos = metaDataControl.getProviderInfos();
        assertThat(infos).containsOnly(providerMetaDataMock1, providerMetaDataMock2);
    }

    @Test
    public void getProviderMetaData() {
        beanManagerFake.registerBean(providerMetaDataMock1, OAuth2ProviderMetaData.class);
        beanManagerFake.registerBean(providerMetaDataMock2, OAuth2ProviderMetaData.class);
        beanManagerFake.endRegistration();
        metaDataControl.init();

        when(providerMetaDataMock1.getName()).thenReturn("dummy1");
        when(providerMetaDataMock2.getName()).thenReturn("dummy2");
        OAuth2ProviderMetaData metaData = metaDataControl.getProviderMetaData("dummy2");

        assertThat(metaData).isEqualTo(providerMetaDataMock2);

    }

    @Test
    public void getProviderMetaData_singleProvider() {
        beanManagerFake.registerBean(providerMetaDataMock2, OAuth2ProviderMetaData.class);
        beanManagerFake.endRegistration();
        metaDataControl.init();

        when(providerMetaDataMock2.getName()).thenReturn("dummy2");
        OAuth2ProviderMetaData metaData = metaDataControl.getProviderMetaData("dummy2");

        assertThat(metaData).isEqualTo(providerMetaDataMock2);
    }

    @Test(expected = AtbashUnexpectedException.class)
    public void getProviderMetaData_UnknownProvider() {
        beanManagerFake.registerBean(providerMetaDataMock1, OAuth2ProviderMetaData.class);
        beanManagerFake.registerBean(providerMetaDataMock2, OAuth2ProviderMetaData.class);
        beanManagerFake.endRegistration();
        metaDataControl.init();

        when(providerMetaDataMock1.getName()).thenReturn("dummy1");
        when(providerMetaDataMock2.getName()).thenReturn("dummy2");

        metaDataControl.getProviderMetaData("dummy3");

    }

    @Test
    public void getSingleProviderMetaData() {
        beanManagerFake.registerBean(providerMetaDataMock1, OAuth2ProviderMetaData.class);
        beanManagerFake.endRegistration();
        metaDataControl.init();

        OAuth2ProviderMetaData metaData = metaDataControl.getSingleProviderMetaData();
        assertThat(metaData).isEqualTo(providerMetaDataMock1);
    }

    @Test(expected = AtbashIllegalActionException.class)
    public void getSingleProviderMetaData_multipleProvider() {
        beanManagerFake.registerBean(providerMetaDataMock1, OAuth2ProviderMetaData.class);
        beanManagerFake.registerBean(providerMetaDataMock2, OAuth2ProviderMetaData.class);
        beanManagerFake.endRegistration();
        metaDataControl.init();

        metaDataControl.getSingleProviderMetaData();
    }

}