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
package be.atbash.ee.security.octopus.async;


import be.atbash.ee.security.octopus.context.OctopusSecurityContext;

import jakarta.enterprise.inject.Model;
import jakarta.faces.application.FacesMessage;
import jakarta.faces.context.FacesContext;
import jakarta.inject.Inject;

/**
 *
 */
@Model
public class PageBean {

    @Inject
    private DemoService demoService;

    @Inject
    private OctopusSecurityContext octopusSecurityContext;

    private String text;
    private String textSystem;

    public void testAsync() {
        try {
            text = demoService.sayHello();
        } catch (Exception e) {
            handleException(e);
        }
    }

    public String getText() {
        return text;
    }

    public void testSystemAccount() {
        try {
            octopusSecurityContext.activateSystemAccount("Demo");
            textSystem = demoService.fromMachine();
        } catch (Exception e) {
            handleException(e);
        }
    }

    private void handleException(Exception e) {
        String msg = "Exception = " + e.getClass().getSimpleName() + " - message = " + e.getMessage();
        FacesContext facesContext = FacesContext.getCurrentInstance();
        facesContext.addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, msg));

    }

    public String getTextSystem() {
        return textSystem;
    }
}
