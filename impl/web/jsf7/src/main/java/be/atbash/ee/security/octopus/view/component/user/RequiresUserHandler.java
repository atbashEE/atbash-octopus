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
package be.atbash.ee.security.octopus.view.component.user;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.view.component.OctopusComponentHandler;
import be.atbash.ee.security.octopus.view.component.secured.OctopusHandlerHelper;
import be.atbash.ee.security.octopus.view.component.secured.SecuredComponentHandler;
import be.atbash.util.ComponentUtils;

import javax.faces.component.UIComponent;
import javax.faces.view.facelets.ComponentConfig;
import java.util.List;

/**
 *
 */
public class RequiresUserHandler extends OctopusComponentHandler {

    public RequiresUserHandler(ComponentConfig config) {
        super(config);
    }

    @Override
    protected void handleComponentSecurity(UIComponent component, UIComponent parent) {
        Boolean not = ComponentUtils.getAttributeValue(component, "not", Boolean.class);
        if (not == null) {
            not = Boolean.FALSE;
        }

        String target = ComponentUtils.getAttributeValue(component, "for", String.class);

        OctopusHandlerHelper.CollectAndRelocateInfoOnTargets callback = new OctopusHandlerHelper.CollectAndRelocateInfoOnTargets(component);
        ComponentUtils.processTargets(parent, target, callback);
        List<UIComponent> targets = callback.getTargets();

        Subject currentUser = SecurityUtils.getSubject();
        boolean isUser = currentUser.isAuthenticated();

        // Remembered property, see issue #53
        if (!isUser) {
            Boolean remembered = ComponentUtils.getAttributeValue(component, "remembered", Boolean.class);
            if (remembered == null) {
                remembered = Boolean.FALSE;
            }
            if (remembered && currentUser.isRemembered()) {
                isUser = true;
            }
        }

        boolean notAllowed = !isUser;
        if (not) {
            notAllowed = !notAllowed;
        }

        if (notAllowed) {
            for (UIComponent targetComponent : targets) {
                SecuredComponentHandler.setNoAccess(targetComponent, null);
            }
        }
    }
}
