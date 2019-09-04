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
package be.atbash.ee.security.octopus.logout;

import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.ee.security.octopus.config.OctopusWebConfiguration;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.util.BeanManagerFake;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class LogoutHandlerTest {

    @Mock
    private OctopusJSFConfiguration jsfConfigurationMock;

    @Mock
    private WebSubject webSubjectMock;

    @InjectMocks
    private LogoutHandler logoutHandler;

    private BeanManagerFake beanManagerFake;

    @Before
    public void setup() {
        beanManagerFake = new BeanManagerFake();
    }

    @After
    public void cleanup() {
        beanManagerFake.deregistration();
    }

    @Test
    public void getLogoutPage_noPostProcessors() {
        beanManagerFake.endRegistration();

        logoutHandler.init();

        ThreadContext.bind(webSubjectMock);

        when(jsfConfigurationMock.getLogoutPage()).thenReturn("/logout.xhtml");

        String page = logoutHandler.getLogoutPage();
        assertThat(page).isEqualTo("/logout.xhtml");
    }

    @Test
    public void getLogoutPage_withPostProcessors() {
        beanManagerFake.registerBean(new TestProcessor(), LogoutURLProcessor.class);
        beanManagerFake.endRegistration();

        logoutHandler.init();

        ThreadContext.bind(webSubjectMock);
        when(jsfConfigurationMock.getLogoutPage()).thenReturn("/logout");

        String page = logoutHandler.getLogoutPage();
        assertThat(page).isEqualTo("/logout?fromProcessor");
    }

    private static class TestProcessor implements LogoutURLProcessor {

        @Override
        public String postProcessLogoutUrl(String logoutURL, LogoutParameters parameters) {
            return logoutURL + "?fromProcessor";
        }
    }
}