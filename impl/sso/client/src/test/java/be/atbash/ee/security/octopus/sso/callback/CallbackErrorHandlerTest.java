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

import be.atbash.ee.oauth2.sdk.ErrorObject;
import be.atbash.util.exception.AtbashUnexpectedException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.slf4j.Logger;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class CallbackErrorHandlerTest {

    @Mock
    private HttpServletResponse httpServletResponseMock;

    @Mock
    private PrintWriter printWriterMock;

    @Mock
    private Logger loggerMock;

    @InjectMocks
    private CallbackErrorHandler callbackErrorHandler;

    @Captor
    private ArgumentCaptor<String> stringArgumentCaptor;

    @Test
    public void showErrorMessage() throws IOException {

        when(httpServletResponseMock.getWriter()).thenReturn(printWriterMock);

        ErrorObject errorObject = new ErrorObject("code", "description");
        callbackErrorHandler.showErrorMessage(httpServletResponseMock, errorObject);

        verify(httpServletResponseMock).setStatus(HttpServletResponse.SC_BAD_REQUEST);
        verify(printWriterMock).println(stringArgumentCaptor.capture());
        assertThat(stringArgumentCaptor.getValue()).isEqualTo("code : description");

    }

    @Test(expected = AtbashUnexpectedException.class)
    public void showErrorMessage_exceptionHandling() throws IOException {

        when(httpServletResponseMock.getWriter()).thenThrow(new IOException());

        ErrorObject errorObject = new ErrorObject("code", "description");
        callbackErrorHandler.showErrorMessage(httpServletResponseMock, errorObject);

    }
}