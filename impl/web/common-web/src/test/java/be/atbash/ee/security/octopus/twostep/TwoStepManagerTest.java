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
package be.atbash.ee.security.octopus.twostep;

import be.atbash.ee.security.octopus.subject.WebSubject;
import be.atbash.util.BeanManagerFake;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
public class TwoStepManagerTest {

    private BeanManagerFake beanManagerFake;

    private TwoStepManager manager;

    @Mock
    private TwoStepProvider providerMock;

    @Mock
    private WebSubject webSubjectMock;

    @BeforeEach
    public void setup() {
        beanManagerFake = new BeanManagerFake();
        manager = new TwoStepManager();
    }

    @AfterEach
    public void teardown() {
        beanManagerFake.deregistration();
    }

    @Test
    public void isTwoStepRequired_noProvider() {
        beanManagerFake.endRegistration();
        manager.init();

        assertThat(manager.isTwoStepRequired()).isFalse();
    }

    @Test
    public void isTwoStepRequired() {
        beanManagerFake.registerBean(providerMock, TwoStepProvider.class);
        beanManagerFake.endRegistration();
        manager.init();

        assertThat(manager.isTwoStepRequired()).isTrue();
    }

    @Test
    public void startSecondStep() {
        beanManagerFake.registerBean(providerMock, TwoStepProvider.class);
        beanManagerFake.endRegistration();
        manager.init();

        manager.startSecondStep(webSubjectMock);
        Mockito.verify(providerMock).startSecondStep(null, null);

    }
}