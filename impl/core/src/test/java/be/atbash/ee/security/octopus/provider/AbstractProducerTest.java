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
package be.atbash.ee.security.octopus.provider;

import org.apache.deltaspike.core.util.bean.ImmutableBean;
import org.junit.Rule;
import org.junit.rules.ExpectedException;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import javax.enterprise.inject.AmbiguousResolutionException;
import javax.enterprise.inject.UnsatisfiedResolutionException;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.InjectionPoint;
import java.lang.reflect.Member;

import static org.mockito.Mockito.when;

/**
 *
 */

public class AbstractProducerTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Mock
    protected InjectionPoint injectionPointMock;

    protected void checkAmbigousResolutionException() {
        final Bean<?> bean = new ImmutableBean(String.class, "test", null, null, null, null, false, true, null, "test", null);
        when(injectionPointMock.getBean()).thenAnswer(new Answer<Bean<?>>() {
            @Override
            public Bean<?> answer(InvocationOnMock invocation) throws Throwable {
                return bean;
            }
        });

        Member memberMock = Mockito.mock(Member.class);
        when(injectionPointMock.getMember()).thenReturn(memberMock);

        when(memberMock.getName()).thenReturn("theField");

        thrown.expect(AmbiguousResolutionException.class);
        thrown.expectMessage("java.lang.String");
        thrown.expectMessage("theField");
    }

    protected void checkUnsatisfiedResolutionException() {
        final Bean<?> bean = new ImmutableBean(Long.class, "test", null, null, null, null, false, true, null, "test", null);
        when(injectionPointMock.getBean()).thenAnswer(new Answer<Bean<?>>() {
            @Override
            public Bean<?> answer(InvocationOnMock invocation) throws Throwable {
                return bean;
            }
        });

        Member memberMock = Mockito.mock(Member.class);
        when(injectionPointMock.getMember()).thenReturn(memberMock);

        when(memberMock.getName()).thenReturn("otherField");

        thrown.expect(UnsatisfiedResolutionException.class);
        thrown.expectMessage("java.lang.Long");
        thrown.expectMessage("otherField");
    }


}
