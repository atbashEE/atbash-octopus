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
package be.atbash.ee.security.octopus.view;

import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.logout.LogoutHandler;
import be.atbash.ee.security.octopus.subject.WebSubject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OctopusJSFSecurityContextTest {

    @Mock
    private WebSubject webSubjectMock;

    @Mock
    private LogoutHandler logoutHandlerMock;

    @Mock
    private HttpServletResponse servletResponseMock;

    @InjectMocks
    private OctopusJSFSecurityContext securityContext;

    @Test
    public void logout() throws IOException {
        // test
        // - logout on Subject
        // - redirect to logoutPage

        ThreadContext.bind(webSubjectMock);
        when(webSubjectMock.getServletResponse()).thenReturn(servletResponseMock);

        when(logoutHandlerMock.getLogoutPage()).thenReturn("logoutPage");

        securityContext.logout();

        verify(webSubjectMock).logout();
        verify(servletResponseMock).setStatus(303);
    }

}