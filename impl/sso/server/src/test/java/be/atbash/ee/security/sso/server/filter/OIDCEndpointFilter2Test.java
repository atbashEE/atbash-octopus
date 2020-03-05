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
package be.atbash.ee.security.sso.server.filter;

import be.atbash.ee.security.octopus.filter.authc.AbstractUserFilter;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
public class OIDCEndpointFilter2Test {

    @Mock
    private AbstractUserFilter userFilter;

    @Mock
    private AbstractUserFilter authenticatedFilter;

    @Mock
    private AbstractUserFilter otherFilter;

    private OIDCEndpointFilter endpointFilter;

    private BeanManagerFake beanManagerFake;

    @BeforeEach
    public void setup() {
        endpointFilter = new OIDCEndpointFilter();
        beanManagerFake = new BeanManagerFake();

        configureFilter(userFilter, "user");
        configureFilter(authenticatedFilter, "authenticated");
        configureFilter(otherFilter, "other");
    }

    private void configureFilter(AbstractUserFilter filter, String name) {
        lenient().when(filter.getLoginUrl()).thenReturn("/" + name);
        lenient().when(filter.getName()).thenReturn(name);
    }

    @AfterEach
    public void tearDown() {
        beanManagerFake.deregistration();
    }


    @Test
    public void init_noOtherFilters() {
        beanManagerFake.registerBean(userFilter, AbstractUserFilter.class);
        beanManagerFake.registerBean(authenticatedFilter, AbstractUserFilter.class);
        beanManagerFake.endRegistration();

        endpointFilter.init();
        assertThat(endpointFilter.getLoginUrl()).isEqualTo("/user");

    }

    @Test
    public void init_additionalFilters() {
        beanManagerFake.registerBean(userFilter, AbstractUserFilter.class);
        beanManagerFake.registerBean(authenticatedFilter, AbstractUserFilter.class);
        beanManagerFake.registerBean(otherFilter, AbstractUserFilter.class);
        beanManagerFake.endRegistration();

        endpointFilter.init();
        assertThat(endpointFilter.getLoginUrl()).isEqualTo("/other");

    }


}