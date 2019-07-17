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
package be.atbash.ee.security.octopus.web.url;

import be.atbash.ee.security.octopus.config.OctopusWebConfiguration;
import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.resource.ResourceUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;
import org.slf4j.Logger;

import javax.servlet.ServletContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
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

    @Mock
    private ServletContext servletContextMock;

    @Mock
    private ResourceUtil resourceUtilMock;

    @Mock
    private Logger loggerMock;

    @InjectMocks
    private SecuredURLReader reader;

    private BeanManagerFake beanManagerFake;

    private String correctFile = "#Comment\n" +
            "url1=value1\n" +
            "\n" +
            " url2 = value2\n" +
            "\n" +
            " # This comment is also ok.\n" +
            "\n" +
            "url3 = value with = is supported";

    private String wrongFile = "\n" +
            "url1";

    @Captor
    private ArgumentCaptor<String> stringCaptor;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();
    }

    @After
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void loadData_fileOnly() throws IOException {
        when(octopusWebConfigurationMock.getLocationSecuredURLProperties()).thenReturn("classpath:be/atbash/ee/security/octopus/web/url/correct.file");
        when(resourceUtilMock.getStream(any(String.class), any(ServletContext.class))).thenReturn(new ByteArrayInputStream(correctFile.getBytes()));

        beanManagerFake.endRegistration();

        reader.loadData(servletContextMock);

        testURLValues(reader.getUrlPatterns(), "url1", "url2", "url3");

        assertThat(reader.getUrlPatterns().get("url3")).isEqualTo("value with = is supported");

        Mockito.verifyNoMoreInteractions(loggerMock);
    }

    @Test
    public void loadData_wrongEntry() throws IOException {
        when(octopusWebConfigurationMock.getLocationSecuredURLProperties()).thenReturn("classpath:be/atbash/ee/security/octopus/web/url/wrong.file");
        when(resourceUtilMock.getStream(any(String.class), any(ServletContext.class))).thenReturn(new ByteArrayInputStream(wrongFile.getBytes()));

        beanManagerFake.endRegistration();

        try {
            reader.loadData(servletContextMock);
            fail("File contains wrong entry and should throw Exception");
        } catch (ConfigurationException e) {
            assertThat(e.getMessage()).isEqualTo("Wrong line within classpath:be/atbash/ee/security/octopus/web/url/wrong.file file -> url1");
        }
        Mockito.verifyNoMoreInteractions(loggerMock);
    }

    @Test
    public void loadData_fileAndProgrammatic() throws IOException {
        when(octopusWebConfigurationMock.getLocationSecuredURLProperties()).thenReturn("classpath:be/atbash/ee/security/octopus/web/url/correct.file");
        when(resourceUtilMock.getStream(any(String.class), any(ServletContext.class))).thenReturn(new ByteArrayInputStream(correctFile.getBytes()));

        LinkedHashMap<String, String> entries = new LinkedHashMap<>();
        entries.put("extra1", "extra value1");
        entries.put("extra2", "extra value2");
        when(urlProviderMock.getURLEntriesToAdd()).thenReturn(entries);
        beanManagerFake.registerBean(urlProviderMock, ProgrammaticURLProtectionProvider.class);
        beanManagerFake.endRegistration();

        reader.loadData(servletContextMock);

        testURLValues(reader.getUrlPatterns(), "extra1", "extra2", "url1", "url2", "url3");
        Mockito.verifyNoMoreInteractions(loggerMock);
    }

    @Test
    public void loadData_fileAndMultipleProgrammatic() throws IOException {
        when(octopusWebConfigurationMock.getLocationSecuredURLProperties()).thenReturn("classpath:be/atbash/ee/security/octopus/web/url/correct.file");
        when(resourceUtilMock.getStream(any(String.class), any(ServletContext.class))).thenReturn(new ByteArrayInputStream(correctFile.getBytes()));

        LinkedHashMap<String, String> entries = new LinkedHashMap<>();
        entries.put("extra1", "extra value1");
        entries.put("extra2", "extra value2");
        when(urlProviderMock.getURLEntriesToAdd()).thenReturn(entries);
        beanManagerFake.registerBean(urlProviderMock, ProgrammaticURLProtectionProvider.class);

        beanManagerFake.registerBean(new TestURLProtectionProvider(), ProgrammaticURLProtectionProvider.class);

        beanManagerFake.endRegistration();

        reader.loadData(servletContextMock);

        // the firstx values need to come first as that provider has value 100 and the Mock one no defined when and thus 1000.
        testURLValues(reader.getUrlPatterns(), "first1", "first2", "extra1", "extra2", "url1", "url2", "url3");
        Mockito.verifyNoMoreInteractions(loggerMock);
    }

    @Test
    public void loadData_unknownFile() throws IOException {
        when(octopusWebConfigurationMock.getLocationSecuredURLProperties()).thenReturn("classpath:be/atbash/ee/security/octopus/web/url/unknown.file");
        when(resourceUtilMock.getStream(any(String.class), any(ServletContext.class))).thenReturn(null);

        beanManagerFake.endRegistration();

        reader.loadData(servletContextMock);

        Mockito.verify(loggerMock).warn(stringCaptor.capture());
        assertThat(stringCaptor.getValue()).isEqualTo("Unable to read contents from classpath:be/atbash/ee/security/octopus/web/url/unknown.file");
    }

    private void testURLValues(Map<String, String> urlPatterns, String... expectedURLs) {
        assertThat(urlPatterns).hasSize(expectedURLs.length);
        List<String> urls = new ArrayList<>();
        for (Map.Entry<String, String> entry : urlPatterns.entrySet()) {
            urls.add(entry.getKey());
        }
        assertThat(urls).containsExactly(expectedURLs);
    }

    @URLProtectionProviderOrder(100)
    private static class TestURLProtectionProvider implements ProgrammaticURLProtectionProvider {

        @Override
        public LinkedHashMap<String, String> getURLEntriesToAdd() {
            LinkedHashMap<String, String> entries = new LinkedHashMap<>();
            entries.put("first1", "first value1");
            entries.put("first2", "first value2");

            return entries;
        }
    }
}