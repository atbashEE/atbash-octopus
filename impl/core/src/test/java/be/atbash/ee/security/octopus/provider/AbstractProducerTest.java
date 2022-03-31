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
package be.atbash.ee.security.octopus.provider;

import org.apache.deltaspike.core.util.bean.ImmutableBean;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.function.Executable;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.stubbing.Answer;

import jakarta.enterprise.inject.AmbiguousResolutionException;
import jakarta.enterprise.inject.UnsatisfiedResolutionException;
import jakarta.enterprise.inject.spi.Bean;
import jakarta.enterprise.inject.spi.InjectionPoint;
import java.lang.reflect.Member;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 *
 */

public class AbstractProducerTest {

    @Mock
    protected InjectionPoint injectionPointMock;

    protected void testWithMultiple(Executable testMethod) {
        final Bean<?> bean = new ImmutableBean(String.class, "test", null, null, null, null, false, true, null, "test", null);
        when(injectionPointMock.getBean()).thenAnswer((Answer<Bean<?>>) invocation -> bean);

        Member memberMock = Mockito.mock(Member.class);
        when(injectionPointMock.getMember()).thenReturn(memberMock);

        when(memberMock.getName()).thenReturn("theField");

        AmbiguousResolutionException exception = Assertions.assertThrows(AmbiguousResolutionException.class, testMethod);
        assertThat(exception.getMessage()).contains("java.lang.String");
        assertThat(exception.getMessage()).contains("theField");

        // FIXME What is the real test here?
    }

    protected void testWithMissing(Executable testMethod) {
        final Bean<?> bean = new ImmutableBean(Long.class, "test", null, null, null, null, false, true, null, "test", null);
        when(injectionPointMock.getBean()).thenAnswer((Answer<Bean<?>>) invocation -> bean);

        Member memberMock = Mockito.mock(Member.class);
        when(injectionPointMock.getMember()).thenReturn(memberMock);

        when(memberMock.getName()).thenReturn("otherField");

        UnsatisfiedResolutionException exception = Assertions.assertThrows(UnsatisfiedResolutionException.class, testMethod);

        assertThat(exception.getMessage()).contains("java.lang.Long");
        assertThat(exception.getMessage()).contains("otherField");

        // FIXME What is the real test here?
    }


}
