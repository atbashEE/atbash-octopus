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
package be.atbash.ee.security.octopus.view.component.secured;

import be.atbash.util.JsfUtils;

import javax.el.MethodExpression;
import javax.faces.component.UIComponent;
import javax.faces.view.facelets.FaceletContext;
import javax.faces.view.facelets.TagConfig;

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

            MethodExpression listener = JsfUtils.createMethodExpression(getAttribute("listener").getValue(), Void.class, UIComponent.class);
            listener.invoke(ctx.getFacesContext().getELContext(), new Object[]{parent});
        }

    }

}