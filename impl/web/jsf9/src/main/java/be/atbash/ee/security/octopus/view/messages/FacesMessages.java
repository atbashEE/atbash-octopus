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
package be.atbash.ee.security.octopus.view.messages;

import be.atbash.util.CDIUtils;
import org.apache.deltaspike.core.api.message.MessageContext;
import org.apache.deltaspike.core.util.StringUtils;

import jakarta.enterprise.context.Dependent;
import jakarta.faces.application.FacesMessage;
import jakarta.faces.component.UIComponent;
import jakarta.faces.component.UIInput;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Inject;
import java.io.Serializable;

/**
 *
 */
@Dependent
//@PublicAPI
public class FacesMessages implements Serializable {

    private String template;
    private String text;
    private Serializable[] arguments;
    private String clientId;
    private FacesMessage.Severity severity;

    @Inject
    private MessageContext messageContext;

    public FacesMessages template(String template) {
        if (!template.startsWith("{") && !template.endsWith("}")) {
            if (template.contains(" ")) {
                text = template; // When it doesn't start with { (and end with } ) and contains spaces -> just text.
            } else {
                this.template = "{" + template + "}";
            }
        } else {
            this.template = template;

        }
        return this;
    }

    public FacesMessages withArguments(Serializable... arguments) {
        this.arguments = arguments;
        return this;
    }

    public FacesMessages text(String text) {
        this.text = text;
        return this;
    }

    public FacesMessages on(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public FacesMessages asError() {
        severity = FacesMessage.SEVERITY_ERROR;
        return this;
    }

    public FacesMessages asInfo() {
        severity = FacesMessage.SEVERITY_INFO;
        return this;
    }

    public FacesMessages asWarn() {
        severity = FacesMessage.SEVERITY_WARN;
        return this;
    }

    public FacesMessages as(FacesMessage.Severity severity) {
        this.severity = severity;
        return this;
    }

    private FacesMessage.Severity determineSeverity(String key) {
        FacesMessage.Severity result = FacesMessage.SEVERITY_INFO;
        String[] parts = key.substring(1).split("\\.");
        result = checkSeverity(result, parts[0], "error", FacesMessage.SEVERITY_ERROR);
        result = checkSeverity(result, parts[0], "warn", FacesMessage.SEVERITY_WARN);
        result = checkSeverity(result, parts[0], "fatal", FacesMessage.SEVERITY_FATAL);
        return result;
    }

    private FacesMessage.Severity checkSeverity(FacesMessage.Severity currentSeverity, String part, String severityText, FacesMessage.Severity severity) {
        FacesMessage.Severity result = currentSeverity;
        if (severityText.equalsIgnoreCase(part)) {
            result = severity;
        }
        return result;
    }

    public void show() {
        FacesContext instance = FacesContext.getCurrentInstance();

        String msg;
        if (StringUtils.isEmpty(template)) {
            msg = text;
            if (severity == null) {  // If we are using text, and the developer didn't specify a severity => Assume ERROR.
                severity = FacesMessage.SEVERITY_ERROR;
            }
        } else {
            msg = messageContext.message().template(template).argument(arguments).toString();

            if (severity == null) {
                severity = determineSeverity(template);
            }
        }
        instance.addMessage(clientId, new FacesMessage(severity, msg, msg));
        if (clientId != null) {
            UIComponent component = instance.getViewRoot().findComponent(clientId);
            if (component instanceof UIInput && FacesMessage.SEVERITY_ERROR.equals(severity)) {
                ((UIInput) component).setValid(false);
            }
        }
        resetData();
    }

    public String text() {
        String result = messageContext.message().template(template).argument(arguments).toString();
        resetData();
        return result;
    }

    public FacesMessage facesMessage() {
        String msg = messageContext.message().template(template).argument(arguments).toString();
        if (severity == null) {
            severity = determineSeverity(template);
        }
        FacesMessage result = new FacesMessage(severity, msg, msg);

        resetData();
        return result;
    }

    private void resetData() {
        template = null;
        text = null;
        arguments = null;
        clientId = null;
        severity = null;
    }

    public static FacesMessages getInstance() {
        return CDIUtils.retrieveInstance(FacesMessages.class);
    }
}
