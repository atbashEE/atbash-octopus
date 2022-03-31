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
package be.atbash.ee.security.octopus.util;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@ExtendWith(MockitoExtension.class)
public class URLUtilTest {

    private URLUtil util;

    @Mock
    private HttpServletRequest requestMock;

    @BeforeEach
    public void setup() {
        util = new URLUtil();
    }

    @Test
    public void determineRoot() throws URISyntaxException {

        URI base = new URI("http://some.server/oidc/data/");
        String root = util.determineRoot(base);

        assertThat(root).isEqualTo("http://some.server/oidc");
    }

    @Test
    public void determineRoot_specialDeployment() throws URISyntaxException {
        // When the app is deployed without a root
        URI base = new URI("http://some.server/login.xhtml");
        String root = util.determineRoot(base);

        assertThat(root).isEqualTo("http://some.server");
    }

    @Test
    public void determineRoot_defaultPort() throws URISyntaxException {

        URI base = new URI("http://some.server:80/oidc/data/");
        String root = util.determineRoot(base);

        assertThat(root).isEqualTo("http://some.server:80/oidc");
    }

    @Test
    public void determineRoot_defaultSecurePort() throws URISyntaxException {

        URI base = new URI("http://some.server:443/oidc/data/");
        String root = util.determineRoot(base);

        assertThat(root).isEqualTo("http://some.server:443/oidc");
    }

    @Test
    public void determineRoot_servletRequest() throws URISyntaxException {

        when(requestMock.getScheme()).thenReturn("http");
        when(requestMock.getServerName()).thenReturn("some.server");
        when(requestMock.getServerPort()).thenReturn(80);
        when(requestMock.getContextPath()).thenReturn("/oidc");
//        when(requestMock.getServletPath()).thenReturn("data");
        String root = util.determineRoot(requestMock);

        assertThat(root).isEqualTo("http://some.server/oidc");
    }

    @Test
    public void determineRoot_servletRequest_nonDefaultPort() throws URISyntaxException {

        when(requestMock.getScheme()).thenReturn("http");
        when(requestMock.getServerName()).thenReturn("some.server");
        when(requestMock.getServerPort()).thenReturn(8080);
        when(requestMock.getContextPath()).thenReturn("/oidc");
//        when(requestMock.getServletPath()).thenReturn("data");
        String root = util.determineRoot(requestMock);

        assertThat(root).isEqualTo("http://some.server:8080/oidc");
    }

}