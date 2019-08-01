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
package be.atbash.ee.security.sso.server.client;

import be.atbash.util.exception.AtbashUnexpectedException;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class ClientInfoTest {
    @Test
    public void getActualCallbackURL_octopusClient() {
        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2/");
        clientInfo.setOctopusClient(true);

        assertThat(clientInfo.getActualCallbackURL()).isEqualTo("http://localhost:8080/sso-app2/sso/SSOCallback");
        assertThat(clientInfo.hasMultipleCallbackURL()).isFalse();
    }

    @Test
    public void getActualCallbackURL_otherClient() {
        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2/data");
        clientInfo.setOctopusClient(false);

        assertThat(clientInfo.getActualCallbackURL()).isEqualTo("http://localhost:8080/sso-app2/data");
    }

    @Test
    public void processCallbackURL_removeTrailingSlash() {
        ClientInfo clientInfo = new ClientInfo();

        clientInfo.setCallbackURL("http://localhost:8080/sso-app2/");

        assertThat(clientInfo.getCallbackURL()).isEqualTo("http://localhost:8080/sso-app2");

    }

    @Test
    public void processCallbackURL_Normalized() {
        ClientInfo clientInfo = new ClientInfo();

        clientInfo.setCallbackURL("http://localhost:8080/sso-app2/./test/../other");

        assertThat(clientInfo.getCallbackURL()).isEqualTo("http://localhost:8080/sso-app2/other");

    }

    @Test(expected = AtbashUnexpectedException.class)
    public void processCallbackURL_WrongURI() {
        ClientInfo clientInfo = new ClientInfo();
        clientInfo.setCallbackURL("://localhost:8080/sso-app2");
    }

    @Test(expected = ClientInfoCallbackException.class)
    public void additionalCallbackURL_noMainURL() {
        ClientInfo clientInfo = new ClientInfo();

        clientInfo.additionalCallbackURL("http://localhost:8080/sso-app2/");

    }

    @Test
    public void additionalCallbackURL_happyCase() {
        ClientInfo clientInfo = new ClientInfo();

        clientInfo.setCallbackURL("http://localhost:8080/sso-app2/");
        clientInfo.additionalCallbackURL("http://alias/sso-app2/");

        assertThat(clientInfo.hasMultipleCallbackURL()).isTrue();
        assertThat(clientInfo.getCallbackURL()).isEqualTo("http://localhost:8080/sso-app2");
        assertThat(clientInfo.getAdditionalCallbackURLs()).containsOnly("http://alias/sso-app2");
    }

    @Test
    public void additionalCallbackURL_octopusClient() {
        ClientInfo clientInfo = new ClientInfo();

        clientInfo.setOctopusClient(true);
        clientInfo.setCallbackURL("http://localhost:8080/sso-app2/");
        clientInfo.additionalCallbackURL("http://alias/sso-app2/");

        assertThat(clientInfo.hasMultipleCallbackURL()).isTrue();
        assertThat(clientInfo.getCallbackURL()).isEqualTo("http://localhost:8080/sso-app2");
        assertThat(clientInfo.getAdditionalCallbackURLs()).containsOnly("http://alias/sso-app2/sso/SSOCallback");
    }

    @Test(expected = ClientInfoOctopusClientException.class)
    public void additionalCallbackURL_changedOctopusClient() {
        ClientInfo clientInfo = new ClientInfo();

        clientInfo.setCallbackURL("http://localhost:8080/sso-app2/");
        clientInfo.additionalCallbackURL("http://alias/sso-app2/");
        clientInfo.setOctopusClient(true);
        clientInfo.additionalCallbackURL("http://alias2/sso-app2/");

    }

}