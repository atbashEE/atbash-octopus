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
package be.atbash.ee.security.octopus.filter.mgt;

import be.atbash.ee.security.octopus.filter.AdviceFilter;
import be.atbash.ee.security.octopus.filter.GlobalFilterProvider;
import be.atbash.ee.security.octopus.filter.PathConfigProcessor;
import be.atbash.util.TestReflectionUtils;
import org.junit.Test;

import javax.servlet.Filter;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */

public class FilterChainManagerTest {

    private FilterChainManager filterChainManager;

    private Map<String, AdviceFilter> filters;

    @Test
    public void createChain_happyCase() throws IllegalAccessException {
        filterChainManager = new FilterChainManager();
        init("ef", "sh", "user", "np");
        initGlobalFilter(false);

        filterChainManager.createChain("pages/**", "user, np[permission:read:*]");

        NamedFilterList chain = filterChainManager.getChain("/pages/**");
        assertThat(chain).isNotNull(); // Test 1 : / is added in front of path
        assertThat(chain).hasSize(3); // 2 defined + ef
        assertThat(chain.get(0).getName()).isEqualTo("ef"); // ef always added
        assertThat(chain.get(1).getName()).isEqualTo("user");
        assertThat(chain.get(2).getName()).isEqualTo("np");
        assertThat(((TestFilter) chain.get(2)).config).isEqualTo("permission:read:*");

    }

    @Test
    public void createChain_AdditionalGlobal() throws IllegalAccessException {
        filterChainManager = new FilterChainManager();
        init("ef", "sh", "user", "np", "test", "audit", "f2");
        initGlobalFilter(true);

        filterChainManager.createChain("pages/**", "user, np[permission:read:*]");

        NamedFilterList chain = filterChainManager.getChain("/pages/**");
        assertThat(chain).hasSize(6); // 2 defined + ef + 3 global
        assertThat(chain.get(0).getName()).isEqualTo("ef");
        assertThat(chain.get(1).getName()).isEqualTo("audit");
        assertThat(chain.get(2).getName()).isEqualTo("test");
        assertThat(chain.get(3).getName()).isEqualTo("f2");
        assertThat(chain.get(4).getName()).isEqualTo("user");
        assertThat(chain.get(5).getName()).isEqualTo("np");

    }

    @Test
    public void createChain_checkFilterConfigParsing() throws IllegalAccessException {
        filterChainManager = new FilterChainManager();
        init("ef", "sh", "user", "np", "test", "audit", "f2");
        initGlobalFilter(false);

        filterChainManager.createChain("pages/**", "user, np[permission:read:*], test[a,b]");

        NamedFilterList chain = filterChainManager.getChain("/pages/**");
        assertThat(chain).hasSize(4);
        assertThat(((TestFilter) chain.get(3)).config).isEqualTo("a,b");

    }

    private void initGlobalFilter(boolean available) throws IllegalAccessException {
        List<GlobalFilterProvider> filterProviders = new ArrayList<>();
        if (available) {
            // Order is important, it determines the order filters are added
            filterProviders.add(new AuditGlobalFilterProvider());
            filterProviders.add(new TestGlobalFilterProvider());
        }
        TestReflectionUtils.injectDependencies(filterChainManager, filterProviders);
    }

    private void init(String... names) throws IllegalAccessException {
        filters = new HashMap<>();
        for (String name : names) {
            TestFilter filter = new TestFilter();
            filter.setName(name);
            filters.put(name, filter);
        }

        TestReflectionUtils.injectDependencies(filterChainManager, filters);
    }

    private class TestFilter extends AdviceFilter implements PathConfigProcessor {

        private String config;

        @Override
        public Filter processPathConfig(String path, String config) {
            this.config = config;
            return this;
        }

    }

    private class TestGlobalFilterProvider implements GlobalFilterProvider {

        @Override
        public List<String> addFiltersTo(String url) {
            return Arrays.asList("test", "f2");
        }
    }

    private class AuditGlobalFilterProvider implements GlobalFilterProvider {

        @Override
        public List<String> addFiltersTo(String url) {
            return Arrays.asList("audit");
        }
    }
}