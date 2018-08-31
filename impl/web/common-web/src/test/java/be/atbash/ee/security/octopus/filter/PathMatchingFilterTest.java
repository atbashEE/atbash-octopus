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
package be.atbash.ee.security.octopus.filter;

import be.atbash.util.TestReflectionUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.nio.file.PathMatcher;

import static be.atbash.ee.security.octopus.filter.FilterChainResolver.OCTOPUS_CHAIN_NAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class PathMatchingFilterTest {

    @Mock
    private PathMatcher pathMatcherMock;

    @Mock
    private ServletRequest servletRequestMock;

    private TestPathMatchingFilter filter;

    @Before
    public void setup() throws IllegalAccessException {
        filter = new TestPathMatchingFilter();
        TestReflectionUtils.injectDependencies(filter, pathMatcherMock);
    }

    @Test
    public void onPreHandle_PathWithNoConfig() throws Exception {
        filter.processPathConfig("/path", null);
        when(servletRequestMock.getAttribute(OCTOPUS_CHAIN_NAME)).thenReturn("/path");

        filter.setOnPreHandleResult(true);

        boolean value = filter.preHandle(servletRequestMock, null);
        assertThat(value).isTrue(); // matched the value set by setOnPreHandleResult()
        assertThat(filter.getMappedValue()).isNull();
    }

    @Test
    public void onPreHandle_PathWithNoConfigRegistered() throws Exception {
        when(servletRequestMock.getAttribute(OCTOPUS_CHAIN_NAME)).thenReturn("/path");

        filter.setOnPreHandleResult(true);

        boolean value = filter.preHandle(servletRequestMock, null);
        assertThat(value).isTrue(); // matched the value set by setOnPreHandleResult()
        assertThat(filter.getMappedValue()).isNull();
    }

    @Test
    public void onPreHandle_PathMultipleConfig1() throws Exception {
        // This test is here to see if we take value from attribute and not using matches (as it was previously)
        filter.processPathConfig("/path/**", "value1");
        filter.processPathConfig("/path/test/**", "value2");
        when(servletRequestMock.getAttribute(OCTOPUS_CHAIN_NAME)).thenReturn("/path/**");

        filter.setOnPreHandleResult(true);

        boolean value = filter.preHandle(servletRequestMock, null);
        assertThat(value).isTrue(); // matched the value set by setOnPreHandleResult()
        assertThat(filter.getMappedValue()).isEqualTo(new String[]{"value1"});
    }

    @Test
    public void onPreHandle_PathMultipleConfig2() throws Exception {

        filter.processPathConfig("/path/**", "value1");
        filter.processPathConfig("/path/test/**", "value2");
        when(servletRequestMock.getAttribute(OCTOPUS_CHAIN_NAME)).thenReturn("/path/test/**");

        filter.setOnPreHandleResult(false);

        boolean value = filter.preHandle(servletRequestMock, null);
        assertThat(value).isFalse(); // matched the value set by setOnPreHandleResult()
        assertThat(filter.getMappedValue()).isEqualTo(new String[]{"value2"});
    }

    @Test
    public void onPreHandle_noAttribute() throws Exception {

        filter.setOnPreHandleResult(false);  // So that we can see that this value is not used

        boolean value = filter.preHandle(servletRequestMock, null);
        assertThat(value).isTrue(); // always
        assertThat(filter.getMappedValue()).isEqualTo("DefaultUnsetValue");
    }

    @Test
    public void onPreHandle_notEnabled() throws Exception {

        filter.processPathConfig("/path", null);
        when(servletRequestMock.getAttribute(OCTOPUS_CHAIN_NAME)).thenReturn("/path");

        filter.setOnPreHandleResult(false);
        filter.setNotEnabled();

        boolean value = filter.preHandle(servletRequestMock, null);
        assertThat(value).isTrue(); // always
        assertThat(filter.getMappedValue()).isEqualTo("DefaultUnsetValue");
    }

    private static class TestPathMatchingFilter extends PathMatchingFilter {

        private boolean onPreHandleResult;
        private Object mappedValue = "DefaultUnsetValue";
        private boolean isEnabledResult = true;

        @Override
        protected boolean onPreHandle(ServletRequest request, ServletResponse response, Object mappedValue) throws Exception {
            this.mappedValue = mappedValue;
            return onPreHandleResult;
        }

        @Override
        protected boolean isEnabled(ServletRequest request, ServletResponse response, String path, Object mappedValue) throws Exception {
            return isEnabledResult;
        }

        void setOnPreHandleResult(boolean onPreHandleResult) {
            this.onPreHandleResult = onPreHandleResult;
        }

        void setNotEnabled() {
            isEnabledResult = false;
        }

        Object getMappedValue() {
            return mappedValue;
        }
    }
}