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
package be.atbash.ee.security.octopus.provider;

import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.subject.UserPrincipal;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;


@RunWith(MockitoJUnitRunner.class)
public class ProducerBeanTest {

    private ProducerBean producerBean = new ProducerBean();

    @Mock
    private Subject subjectMock;

    @Mock
    private UserPrincipal userPrincipalMock;

    @Before
    public void setup() {
        ThreadContext.bind(subjectMock);
    }

    @Test
    public void producePrincipal() {
        when(subjectMock.getPrincipal()).thenReturn(userPrincipalMock);
        UserPrincipal userPrincipal = producerBean.producePrincipal();
        assertThat(userPrincipal).isNotNull();
        assertThat(userPrincipal).isSameAs(userPrincipalMock);
    }

    @Test
    public void producePrincipal_emptyPrincipal() {
        ThreadContext.remove(); // The Mock is now removed and thus null

        UserPrincipal userPrincipal = producerBean.producePrincipal();
        assertThat(userPrincipal).isNotNull();
        assertThat(userPrincipal).isNotSameAs(userPrincipalMock);
    }

    @Test
    public void produceUser() {
        when(subjectMock.getPrincipal()).thenReturn(userPrincipalMock);
        when(userPrincipalMock.getName()).thenReturn("JUnit");

        String name = producerBean.produceUser();
        assertThat(name).isEqualTo("JUnit");
    }

    @Test
    public void produceUser_emptyPrincipal() {
        ThreadContext.remove(); // The Mock is now removed and thus null

        String name = producerBean.produceUser();
        assertThat(name).isNull();
    }
}