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
package be.atbash.ee.security.octopus.filter.authc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class NoneFilterTest {

    @Mock
    private HttpServletResponse responseMock;

    @Mock
    private PrintWriter printWriterMock;

    private NoneFilter filter = new NoneFilter();

    @Test
    public void isAccessAllowed() {
        // null parameter here ok as nothing used
        boolean allowed = filter.isAccessAllowed(null, null);
        assertThat(allowed).isFalse();
    }

    @Test
    public void postHandle() throws Exception {
        when(responseMock.getWriter()).thenReturn(printWriterMock);

        filter.postHandle(null, responseMock);


        verify(responseMock).reset();
        verify(printWriterMock).write(anyString());
    }
}