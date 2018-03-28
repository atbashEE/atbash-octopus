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
package be.atbash.ee.security.octopus.ratelimit;

import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
import be.atbash.util.TestReflectionUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.util.Map;

import static be.atbash.ee.security.octopus.filter.FilterChainResolver.OCTOPUS_CHAIN_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class RateLimitFilterTest {

    private static final String SOMEPATH = "/somepath";
    @Mock
    private ServletRequest requestMock;

    @Mock
    private HttpServletResponse responseMock;

    @Mock
    private FixedBucket fixedBucketMock;

    @Mock
    private PrintWriter printWriterMock;

    private RateLimitFilter filter;

    @Before
    public void setup() {
        filter = new RateLimitFilter();
        filter.initInstance();
    }

    @Test
    public void processPathConfig() throws NoSuchFieldException, IllegalAccessException {
        filter.processPathConfig(SOMEPATH, "1/1s");

        Map<String, FixedBucket> rateLimiters = TestReflectionUtils.getValueOf(filter, "rateLimiters");
        assertThat(rateLimiters).hasSize(1);
        assertThat(rateLimiters).containsKey(SOMEPATH);
        assertThat(rateLimiters.get(SOMEPATH)).isNotNull();
    }

    @Test(expected = ConfigurationException.class)
    public void processPathConfig_invalidConfig() {
        filter.processPathConfig(SOMEPATH, "1/1s, 10/1m");
    }

    @Test
    public void onPreHandle() throws Exception {

        Map<String, FixedBucket> rateLimiters = TestReflectionUtils.getValueOf(filter, "rateLimiters");
        rateLimiters.put(SOMEPATH, fixedBucketMock);

        when(requestMock.getAttribute(OCTOPUS_CHAIN_NAME)).thenReturn(SOMEPATH);
        when(fixedBucketMock.getToken(anyString())).thenReturn(TokenInstance.USABLE);

        filter.onPreHandle(requestMock, responseMock, null);

        verifyNoMoreInteractions(responseMock);
    }

    @Test
    public void onPreHandle_rateExceeded() throws Exception {

        Map<String, FixedBucket> rateLimiters = TestReflectionUtils.getValueOf(filter, "rateLimiters");
        rateLimiters.put(SOMEPATH, fixedBucketMock);

        when(requestMock.getAttribute(OCTOPUS_CHAIN_NAME)).thenReturn(SOMEPATH);
        when(responseMock.getWriter()).thenReturn(printWriterMock);
        when(fixedBucketMock.getToken(anyString())).thenReturn(TokenInstance.UNUSABLE);

        filter.onPreHandle(requestMock, responseMock, null);

        verify(responseMock).setStatus(429);
    }

}