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
package be.atbash.ee.security.octopus.filter;

import be.atbash.ee.security.octopus.subject.support.WebSubjectContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.ServletRequest;

import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
public class NoSessionCreationFilterTest {

    private NoSessionCreationFilter filter = new NoSessionCreationFilter();

    @Mock
    private ServletRequest servletRequestMock;


    @Test
    public void onPreHandle() throws Exception {
        filter.onPreHandle(servletRequestMock, null);

        verify(servletRequestMock).setAttribute(WebSubjectContext.SESSION_CREATION_ENABLED, Boolean.FALSE);
    }
}