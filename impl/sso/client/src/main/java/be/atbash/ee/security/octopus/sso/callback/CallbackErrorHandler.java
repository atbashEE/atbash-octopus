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
import org.slf4j.Logger;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 */
@ApplicationScoped
public class CallbackErrorHandler {

    @Inject
    private Logger logger;

    // Within log info message, there is a mentioning that it is about the SSO callback servlet error messages.
    // So change this when it will be used for other purposes.
    public void showErrorMessage(HttpServletResponse httpServletResponse, ErrorObject errorObject) {
        try {
            httpServletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            httpServletResponse.getWriter().println(errorObject.getCode() + " : " + errorObject.getDescription());

            logger.info(String.format("SSO callback error code = %s, description %s ", errorObject.getCode(), errorObject.getDescription()));
            logger.info("Thread information");
            StackTraceElement[] traceElements = Thread.currentThread().getStackTrace();
            for (int i = 0; i < 4; i++) {
                logger.info(traceElements[i].toString());
            }
        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

    }

}
