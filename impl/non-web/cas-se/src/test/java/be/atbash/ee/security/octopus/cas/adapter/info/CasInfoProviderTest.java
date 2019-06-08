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
package be.atbash.ee.security.octopus.cas.adapter.info;

import be.atbash.config.test.TestConfig;
import be.atbash.ee.security.octopus.cas.adapter.CasUserToken;
import be.atbash.ee.security.octopus.cas.exception.CasAuthenticationException;
import net.jadler.Jadler;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasItem;

public class CasInfoProviderTest {

    private CasInfoProvider infoProvider;

    @Before
    public void setup() {
        Jadler.initJadler();
        configureParameters();
        infoProvider = new CasInfoProvider();
    }

    @After
    public void tearDown() {
        Jadler.closeJadler();
        TestConfig.resetConfig();
    }

    @Test
    public void retrieveUserInfo() {

        Jadler.onRequest()
                .havingPathEqualTo("/cas/p3/serviceValidate")
                .havingParameter("ticket", hasItem("ST1"))
                .havingParameter("service", hasItem("http%3A%2F%2Fsome.server%2Ffictive%2Fcient%2Furl"))
                .respond()
                .withStatus(200)
                .withBody("<cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">\n" +
                        " <cas:authenticationSuccess>\n" +
                        "  <cas:user>username</cas:user>\n" +
                        "   <cas:attributes>\n" +
                        "        <cas:firstname>John</cas:firstname>\n" +
                        "        <cas:lastname>Doe</cas:lastname>\n" +
                        "        <cas:title>Mr.</cas:title>\n" +
                        "        <cas:email>jdoe@example.org</cas:email>\n" +
                        "        <cas:affiliation>staff</cas:affiliation>\n" +
                        "        <cas:affiliation>faculty</cas:affiliation>\n" +
                        "      </cas:attributes>" +
                        "  <cas:proxyGrantingTicket>GT1</cas:proxyGrantingTicket>\n" +
                        " </cas:authenticationSuccess>\n" +
                        "</cas:serviceResponse>");

        CasUserToken userToken = infoProvider.retrieveUserInfo("ST1");

        assertThat(userToken).isNotNull();
        assertThat(userToken.getUserName()).isEqualTo("username");
        assertThat(userToken.getEmail()).isEqualTo("jdoe@example.org");
        assertThat(userToken.getUserInfo()).hasSize(6);
        assertThat(userToken.getUserInfo()).containsOnlyKeys("firstname", "affiliation", "title", "email", "lastname", "upstreamToken");
        List<String> affiliation = (List<String>) userToken.getUserInfo().get("affiliation");
        assertThat(affiliation).containsOnly("staff", "faculty");

    }

    @Test(expected = CasAuthenticationException.class)
    public void retrieveUserInfo_WrongTicket() {

        Jadler.onRequest()
                .havingPathEqualTo("/cas/p3/serviceValidate")
                .havingParameter("ticket", hasItem("ST1"))
                .havingParameter("service", hasItem("http%3A%2F%2Fsome.server%2Ffictive%2Fcient%2Furl"))
                .respond()
                .withStatus(200)
                .withBody("<cas:serviceResponse xmlns:cas=\"http://www.yale.edu/tp/cas\">\n" +
                        " <cas:authenticationFailure code=\"INVALID_TICKET\">\n" +
                        "    Ticket ST1\n" +
                        "  </cas:authenticationFailure>\n" +
                        "</cas:serviceResponse>");

        infoProvider.retrieveUserInfo("ST1");

    }

    private void configureParameters() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put("CAS.SSO.server", "http://localhost:" + Jadler.port() + "/cas");
        parameters.put("CAS.service", "http://some.server/fictive/cient/url");
        TestConfig.addConfigValues(parameters);

    }

}