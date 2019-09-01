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
package be.atbash.ee.security.octopus.filter;

import be.atbash.ee.security.octopus.config.exception.ConfigurationException;
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
import static org.mockito.Mockito.verify;
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
        assertThat(filter.getPathConfig()).isNull();
    }

    @Test
    public void onPreHandle_PathWithNoConfigRegistered() throws Exception {
        when(servletRequestMock.getAttribute(OCTOPUS_CHAIN_NAME)).thenReturn("/path");

        filter.setOnPreHandleResult(true);

        boolean value = filter.preHandle(servletRequestMock, null);
        assertThat(value).isTrue(); // matched the value set by setOnPreHandleResult()
        assertThat(filter.getPathConfig()).isNull();
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
        verify(servletRequestMock).setAttribute("octopus.pathConfig", new String[]{"value1"});
    }

    @Test
    public void onPreHandle_PathMultipleConfig2() throws Exception {

        filter.processPathConfig("/path/**", "value1");
        filter.processPathConfig("/path/test/**", "value2");
        when(servletRequestMock.getAttribute(OCTOPUS_CHAIN_NAME)).thenReturn("/path/test/**");

        filter.setOnPreHandleResult(false);

        boolean value = filter.preHandle(servletRequestMock, null);
        assertThat(value).isFalse(); // matched the value set by setOnPreHandleResult()
        verify(servletRequestMock).setAttribute("octopus.pathConfig", new String[]{"value2"});
    }

    @Test
    public void onPreHandle_noAttribute() throws Exception {

        filter.setOnPreHandleResult(false);  // So that we can see that this value is not used

        boolean value = filter.preHandle(servletRequestMock, null);
        assertThat(value).isTrue(); // always
        assertThat(filter.getPathConfig()).isEqualTo(new String[]{"DefaultUnsetValue"});
    }

    @Test
    public void onPreHandle_notEnabled() throws Exception {

        filter.processPathConfig("/path", null);
        when(servletRequestMock.getAttribute(OCTOPUS_CHAIN_NAME)).thenReturn("/path");

        filter.setOnPreHandleResult(false);
        filter.setNotEnabled();

        boolean value = filter.preHandle(servletRequestMock, null);
        assertThat(value).isTrue(); // always
        assertThat(filter.getPathConfig()).isEqualTo(new String[]{"DefaultUnsetValue"});
    }

    @Test
    public void processPathConfig_singleConfigValue() {
        filter.processPathConfig("/test", "config");
        assertThat(filter.appliedPaths).hasSize(1);
        assertThat(filter.appliedPaths.get("/test")).containsExactly("config");
    }

    @Test
    public void processPathConfig_multiConfigValue() {
        filter.processPathConfig("/test", "config1,config2");
        assertThat(filter.appliedPaths).hasSize(1);
        assertThat(filter.appliedPaths.get("/test")).containsExactly("config1", "config2");
    }

    @Test
    public void processPathConfig_noConfigValue_noRequired() {
        filter.processPathConfig("/test", null);
        assertThat(filter.appliedPaths).hasSize(1);
        assertThat(filter.appliedPaths.get("/test")).isNullOrEmpty();
    }

    @Test
    public void processPathConfig_emptyConfigValue_noRequired() {
        filter.processPathConfig("/test", "");
        assertThat(filter.appliedPaths).hasSize(1);
        assertThat(filter.appliedPaths.get("/test")).isNullOrEmpty();
    }

    @Test
    public void processPathConfig_spacesConfigValue_noRequired() {
        filter.processPathConfig("/test", "    ");
        assertThat(filter.appliedPaths).hasSize(1);
        assertThat(filter.appliedPaths.get("/test")).isNullOrEmpty();
    }

    @Test(expected = ConfigurationException.class)
    public void processPathConfig_noConfigValue_required() {
        filter.setRequiresPathConfiguration(true);
        filter.processPathConfig("/test", null);
    }

    @Test(expected = ConfigurationException.class)
    public void processPathConfig_emptyConfigValue_required() {
        filter.setRequiresPathConfiguration(true);
        filter.processPathConfig("/test", "");
    }

    @Test(expected = ConfigurationException.class)
    public void processPathConfig_spacesConfigValue_required() {
        filter.setRequiresPathConfiguration(true);
        filter.processPathConfig("/test", "    ");
    }

    private static class TestPathMatchingFilter extends PathMatchingFilter {

        private boolean onPreHandleResult;
        private String[] pathConfig = new String[]{"DefaultUnsetValue"};
        private boolean isEnabledResult = true;
        private boolean requiresPathConfiguration = false;

        @Override
        protected boolean onPreHandle(ServletRequest request, ServletResponse response) throws Exception {
            this.pathConfig = getPathConfig(request);
            return onPreHandleResult;
        }

        @Override
        protected boolean isEnabled(ServletRequest request, ServletResponse response, String path) throws Exception {
            return isEnabledResult;
        }

        void setOnPreHandleResult(boolean onPreHandleResult) {
            this.onPreHandleResult = onPreHandleResult;
        }

        void setNotEnabled() {
            isEnabledResult = false;
        }

        public void setRequiresPathConfiguration(boolean requiresPathConfiguration) {
            this.requiresPathConfiguration = requiresPathConfiguration;
        }

        @Override
        protected boolean requiresPathConfiguration() {
            return requiresPathConfiguration;
        }

        Object getPathConfig() {
            return pathConfig;
        }
    }
}