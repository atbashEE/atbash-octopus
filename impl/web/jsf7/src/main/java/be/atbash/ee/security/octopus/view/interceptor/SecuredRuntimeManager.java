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
package be.atbash.ee.security.octopus.view.interceptor;

import be.atbash.ee.security.octopus.view.component.secured.SecuredComponent;
import be.atbash.ee.security.octopus.view.component.secured.SecuredComponentData;
import be.atbash.ee.security.octopus.view.component.service.ComponentAuthorizationService;

import javax.enterprise.context.ApplicationScoped;
import javax.faces.component.UIComponent;
import javax.inject.Inject;
import java.util.HashSet;
import java.util.Set;

/**
 * Class manages those components where at runtime the decision must be made if it shown or not, like h:column.
 */
@ApplicationScoped
public class SecuredRuntimeManager {

    @Inject
    private ComponentAuthorizationService componentAuthorizationService;

    private Set<UIComponent> componentSet = new HashSet<>();

    public void checkRendererStatus(UIComponent uiComponent) {
        if (uiComponent.isRendered() && !allowed(uiComponent)) {
            uiComponent.setRendered(false);
            // Keep an indication that we have changed the state.
            keepComponent(uiComponent);
            componentSet.add(uiComponent);
        }
    }

    private void keepComponent(UIComponent uiComponent) {
        String rendererType = uiComponent.getParent().getRendererType();
        if (rendererType == null) {
            uiComponent.getParent().setRendererType("Dummy");
        }
    }

    /**
     * If there exists a child in the component named SecuredComponent, the the user must have one of the permissions
     * specified in
     * the value attribute of the component.  If no child is found, the viewing is allowed.
     *
     * @param someUiComponent The JSF component we have to evaluate for security.
     * @return Is it allowed to show this component to the user.
     */
    public boolean allowed(final UIComponent someUiComponent) {

        boolean result = true;
        SecuredComponentData data = (SecuredComponentData) someUiComponent.getAttributes().get(SecuredComponent.DATA);
        if (data != null) {
            result = componentAuthorizationService.hasAccess(data);
        }
        return result;
    }

    public void resetRenderedStatus(UIComponent uiComponent) {
        if (!componentSet.isEmpty()) {
            // Try to do something only when there is something to remove -> performance increase.
            for (UIComponent child : uiComponent.getChildren()) {
                if (componentSet.contains(child)) {
                    child.setRendered(true);
                    componentSet.remove(child);
                    if ("Dummy".equals(uiComponent.getRendererType())) {
                        uiComponent.setRendererType(null);
                    }
                }
            }
        }
    }
}
