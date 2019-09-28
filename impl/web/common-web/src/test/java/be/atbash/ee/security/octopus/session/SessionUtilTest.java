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
package be.atbash.ee.security.octopus.session;

import be.atbash.ee.security.octopus.config.OctopusWebConfiguration;
import be.atbash.ee.security.octopus.context.ThreadContext;
import be.atbash.ee.security.octopus.subject.WebSubject;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.junit.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class SessionUtilTest {

    @Mock
    private OctopusWebConfiguration octopusWebConfigurationMock;

    @Mock
    private HttpServletRequest requestMock;

    @Mock
    private HttpSession sessionMock;  // The current Session

    @Mock
    private HttpSession session2Mock;  // The new session

    @Mock
    private WebSubject webSubjectMock;

    @InjectMocks
    private SessionUtil sessionUtil;

    @Test
    public void invalidateCurrentSession() {
        when(octopusWebConfigurationMock.getIsSessionInvalidatedAtLogin()).thenReturn(Boolean.TRUE);

        when(requestMock.getSession()).thenReturn(sessionMock);
        when(requestMock.getSession(true)).thenReturn(session2Mock);

        final Map<String, Object> attributes = new HashMap<>();
        attributes.put("key1", "Value1");
        attributes.put("key2", 42);

        when(sessionMock.getAttributeNames()).thenReturn(new Vector(attributes.keySet()).elements());
        when(sessionMock.getAttribute(anyString())).thenAnswer(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                Object key = invocationOnMock.getArgument(0);
                return attributes.get(key.toString());
            }
        });

        ThreadContext.bind(webSubjectMock);

        sessionUtil.invalidateCurrentSession(requestMock);

        // The values are removed fro Session before session is invalidated.
        verify(sessionMock).removeAttribute("key1");
        verify(sessionMock).removeAttribute("key2");

        verify(webSubjectMock).logout();

        verify(session2Mock).setAttribute("key1", "Value1");
        verify(session2Mock).setAttribute("key2", 42);
    }

    @Test
    public void invalidateCurrentSession_noInvalidation() {
        when(octopusWebConfigurationMock.getIsSessionInvalidatedAtLogin()).thenReturn(Boolean.FALSE);

        ThreadContext.bind(webSubjectMock);

        sessionUtil.invalidateCurrentSession(requestMock);


        verify(requestMock, never()).getSession();
        verify(requestMock, never()).getSession(true);

        verify(webSubjectMock, never()).logout();

    }
}