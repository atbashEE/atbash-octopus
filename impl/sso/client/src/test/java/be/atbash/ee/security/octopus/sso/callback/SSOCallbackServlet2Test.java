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
package be.atbash.ee.security.octopus.sso.callback;

import be.atbash.ee.security.octopus.server.requestor.CustomUserInfoValidator;
import be.atbash.util.BeanManagerFake;
import be.atbash.util.TestReflectionUtils;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.ServletException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SSOCallbackServlet2Test {

    @Mock
    private CustomUserInfoValidator customUserInfoValidatorMock;

    @InjectMocks
    private SSOCallbackServlet ssoCallbackServlet;

    private BeanManagerFake beanManagerFake = new BeanManagerFake();

    @After
    public void tearDown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void init_noCustomValidator() throws ServletException, NoSuchFieldException, IllegalAccessException {
        beanManagerFake.endRegistration();

        ssoCallbackServlet.init();

        Object octopusUserRequestor = TestReflectionUtils.getValueOf(ssoCallbackServlet, "octopusUserRequestor");
        assertThat(octopusUserRequestor).isNotNull();
        Object customUserInfoValidator = TestReflectionUtils.getValueOf(octopusUserRequestor, "customUserInfoValidator");
        assertThat(customUserInfoValidator).isNull();
    }

    @Test
    public void init_withCustomValidator() throws ServletException, NoSuchFieldException, IllegalAccessException {
        beanManagerFake.registerBean(customUserInfoValidatorMock, CustomUserInfoValidator.class);
        beanManagerFake.endRegistration();

        ssoCallbackServlet.init();

        Object octopusUserRequestor = TestReflectionUtils.getValueOf(ssoCallbackServlet, "octopusUserRequestor");
        assertThat(octopusUserRequestor).isNotNull();
        Object customUserInfoValidator = TestReflectionUtils.getValueOf(octopusUserRequestor, "customUserInfoValidator");
        assertThat(customUserInfoValidator).isNotNull();
    }
}