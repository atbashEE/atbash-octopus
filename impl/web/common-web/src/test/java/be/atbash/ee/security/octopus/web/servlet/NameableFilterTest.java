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
package be.atbash.ee.security.octopus.web.servlet;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

public class NameableFilterTest {

    private NameableFilter filter;

    @BeforeEach
    public void setup() {
        filter = new NameableFilter() {
            @Override
            public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

            }
        };
    }

    @Test
    public void setName_noName() {
        // We do not specify any name
        assertThat(filter.getName()).isNull();
        assertThat(filter.getNames()).isEmpty();
    }

    @Test
    public void setName_single() {
        // We only specify a single name, no aliases

        filter.setName("Filter1");

        assertThat(filter.getName()).isEqualTo("Filter1");
        assertThat(filter.getNames()).containsOnly("Filter1");
    }

    @Test
    public void setName_multiple() {
        // The second name we specify is an alias.

        filter.setName("Filter2");
        filter.setName("Filter1");

        assertThat(filter.getName()).isEqualTo("Filter2");
        assertThat(filter.getNames()).containsOnly("Filter1", "Filter2");

    }

    @Test
    public void toString_noName() {
        // We do not specify any name
        assertThat(filter.toString()).isEqualTo(NameableFilterTest.class.getName() + "$1");
    }

    @Test
    public void toString_single() {
        // We only specify a single name, no aliases

        filter.setName("Filter1");

        assertThat(filter.toString()).isEqualTo("Filter1");
    }

    @Test
    public void toString_multiple() {
        // The second name we specify is an alias.
        filter.setName("Filter2");
        filter.setName("Filter1");

        assertThat(filter.toString()).contains("Filter2");
        assertThat(filter.toString()).contains("Filter1");
    }

}
