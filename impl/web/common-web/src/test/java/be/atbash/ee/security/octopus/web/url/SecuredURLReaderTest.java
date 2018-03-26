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
package be.atbash.ee.security.octopus.web.url;

import be.atbash.ee.security.octopus.config.OctopusWebConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SecuredURLReaderTest {

    @Mock
    private OctopusWebConfiguration octopusWebConfigurationMock;

    @Mock
    private ProgrammaticURLProtectionProvider urlProviderMock;

    @InjectMocks
    private SecuredURLReader reader;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void loadData_fileOnly() {
        when(octopusWebConfigurationMock.getLocationSecuredURLProperties()).thenReturn("classpath:be/atbash/ee/security/octopus/web/url/correct.file");

        beanManagerFake.endRegistration();

        reader.loadData(null);

        testURLValues(reader.getUrlPatterns(), "url1", "url2", "url3");

        assertThat(reader.getUrlPatterns().get("url3")).isEqualTo("value with = is supported");

    }

    @Test
    public void loadData_WrongEntry() {
        when(octopusWebConfigurationMock.getLocationSecuredURLProperties()).thenReturn("classpath:be/atbash/ee/security/octopus/web/url/wrong.file");

        beanManagerFake.endRegistration();

        try {
            reader.loadData(null);
            fail("File contains wrong entry and should throw Exception");
        } catch (ConfigurationException e) {
            assertThat(e.getMessage()).isEqualTo("Wrong line within classpath:be/atbash/ee/security/octopus/web/url/wrong.file file -> url1");
        }

    }

    @Test
    public void loadData_fileAndProgrammatic() {
        when(octopusWebConfigurationMock.getLocationSecuredURLProperties()).thenReturn("classpath:be/atbash/ee/security/octopus/web/url/correct.file");

        LinkedHashMap<String, String> entries = new LinkedHashMap<>();
        entries.put("extra1", "extra value1");
        entries.put("extra2", "extra value2");
        when(urlProviderMock.getURLEntriesToAdd()).thenReturn(entries);
        beanManagerFake.registerBean(urlProviderMock, ProgrammaticURLProtectionProvider.class);
        beanManagerFake.endRegistration();

        reader.loadData(null);

        testURLValues(reader.getUrlPatterns(), "extra1", "extra2", "url1", "url2", "url3");

    }

    private void testURLValues(Map<String, String> urlPatterns, String... expectedURLs) {
        assertThat(urlPatterns).hasSize(expectedURLs.length);
        List<String> urls = new ArrayList<>();
        for (Map.Entry<String, String> entry : urlPatterns.entrySet()) {
            urls.add(entry.getKey());
        }
        assertThat(urls).containsExactly(expectedURLs);
    }
}