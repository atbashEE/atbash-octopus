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
package be.atbash.ee.security.octopus.view.component.secured;

import be.atbash.ee.security.octopus.config.OctopusJSFConfiguration;
import be.atbash.util.CDIUtils;
import be.atbash.util.exception.AtbashUnexpectedException;

import jakarta.faces.component.UIComponent;
import jakarta.faces.context.ExternalContext;
import jakarta.faces.view.facelets.FaceletContext;
import jakarta.faces.view.facelets.TagConfig;
import java.io.IOException;

/**
 *
 */
public class SecuredPageHandler extends OctopusTagHandler {

    public SecuredPageHandler(TagConfig config) {
        super(config);
    }

    @Override
    void handleSecurity(FaceletContext ctx, UIComponent parent, SecuredComponentData securedComponentData) {
        if (!octopusHandlerHelper.hasAccess(securedComponentData)) {
            ctx.getFacesContext().responseComplete();

            OctopusJSFConfiguration config = CDIUtils.retrieveInstance(OctopusJSFConfiguration.class);
            ExternalContext externalContext = ctx.getFacesContext().getExternalContext();
            try {
                externalContext.redirect(externalContext.getRequestContextPath() + config.getUnauthorizedExceptionPage());
            } catch (IOException e) {
                // OWASP A6 : Sensitive Data Exposure
                throw new AtbashUnexpectedException(e);
            }

        }
    }
}
