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

import be.atbash.ee.security.octopus.view.component.OctopusComponentUsageException;
import be.atbash.util.JsfUtils;

import jakarta.el.ELException;
import jakarta.el.MethodExpression;
import jakarta.faces.component.UIComponent;
import jakarta.faces.view.facelets.FaceletContext;
import jakarta.faces.view.facelets.TagAttribute;
import jakarta.faces.view.facelets.TagConfig;

/**
 *
 */
public class PermissionListenerHandler extends OctopusTagHandler {

    public PermissionListenerHandler(TagConfig config) {
        super(config);
    }

    @Override
    void handleSecurity(FaceletContext ctx, UIComponent parent, SecuredComponentData securedComponentData) {
        if (octopusHandlerHelper.hasAccess(securedComponentData)) {

            TagAttribute attribute = getAttribute("listener");
            if (attribute == null) {
                throw new OctopusComponentUsageException("The tag securedListener needs a listener attribute that is an EL expression to method with parameter of type UIComponent");
            }
            MethodExpression listener = JsfUtils.createMethodExpression(attribute.getValue(), Void.class, UIComponent.class);
            try {
                listener.invoke(ctx.getFacesContext().getELContext(), new Object[]{parent});
            } catch (ELException e) {
                throw new OctopusComponentUsageException(String.format("The value of listener atribute must be an EL expression to a method with parameter of type UIComponent. Found '%s'", attribute.getValue()));
            }
        }

    }

}
