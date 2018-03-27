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
package be.atbash.ee.security.octopus.exception;

import be.atbash.ee.security.octopus.authz.violation.SecurityAuthorizationViolationException;
import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.util.CDIUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.faces.FacesException;
import javax.faces.application.FacesMessage;
import javax.faces.context.ExceptionHandler;
import javax.faces.context.ExceptionHandlerWrapper;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.event.ExceptionQueuedEvent;
import javax.faces.event.ExceptionQueuedEventContext;
import java.io.IOException;
import java.util.Iterator;

public class AuthorizationExceptionHandler extends ExceptionHandlerWrapper {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationExceptionHandler.class.getCanonicalName());

    private ExceptionHandler wrapped;

    AuthorizationExceptionHandler(ExceptionHandler exception) {
        this.wrapped = exception;
    }

    @Override
    public ExceptionHandler getWrapped() {
        return wrapped;
    }

    @Override
    public void handle() throws FacesException {

        Iterator<ExceptionQueuedEvent> i = getUnhandledExceptionQueuedEvents().iterator();
        while (i.hasNext()) {
            ExceptionQueuedEvent event = i.next();
            Throwable t = getThrowable(event);

            Throwable unauthorized = SecurityAuthorizationViolationException.getUnauthorizedException(t);
            if (unauthorized != null) {
                try {
                    handleAuthorizationException(unauthorized);
                } finally {
                    //remove it from queue
                    i.remove();
                }
            }
        }
        //parent handle
        getWrapped().handle();
    }

    private void handleAuthorizationException(Throwable unauthorized) {
        LOGGER.error("Authorization Exception ", unauthorized);

        FacesContext facesContext = FacesContext.getCurrentInstance();
        ExternalContext externalContext = facesContext.getExternalContext();

        externalContext.getFlash().setKeepMessages(true);
        facesContext.addMessage(null,
                new FacesMessage(FacesMessage.SEVERITY_ERROR, unauthorized.getMessage(), unauthorized.getMessage()));

        if (unauthorized instanceof SecurityAuthorizationViolationException) {

            String exceptionPointInfo = ((SecurityAuthorizationViolationException) unauthorized).getExceptionPointInfo();
            if (exceptionPointInfo != null) {
                exceptionPointInfo = exceptionPointInfo.replaceAll("\n", "<br/>");
            }
            externalContext.getFlash().putNow("interceptionInfo", exceptionPointInfo);
        }
        try {
            OctopusJSFConfiguration config = CDIUtils.retrieveInstance(OctopusJSFConfiguration.class);
            externalContext.redirect(externalContext.getRequestContextPath() + config.getUnauthorizedExceptionPage());

        } catch (IOException e) {
            LOGGER.error("Redirect to unauthorized page failed", e);
        }
        facesContext.renderResponse();
    }

    private Throwable getThrowable(ExceptionQueuedEvent event) {
        ExceptionQueuedEventContext context = (ExceptionQueuedEventContext) event.getSource();

        return context.getException();
    }

}