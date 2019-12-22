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
package be.atbash.ee.security.octopus.view.component.secured;

import be.atbash.util.ComponentUtils;

import javax.faces.component.UIComponent;
import javax.faces.event.SystemEvent;
import javax.faces.event.SystemEventListener;
import java.util.List;

/**
 *
 */
class RelocateSecurityInformationEventListener implements SystemEventListener {

    private UIComponent component;

    RelocateSecurityInformationEventListener(UIComponent someComponent) {
        component = someComponent;
    }

    @Override
    public boolean isListenerForSource(Object source) {
        return true;
    }

    @Override
    public void processEvent(SystemEvent event) {
        SecuredComponentData data = (SecuredComponentData) component.getAttributes().get(SecuredComponent.DATA);
        if (data == null) {
            // We have a PreRenderViewEvent defined in the screen.
            return;
        }
        List<UIComponent> targets = ComponentUtils.findTargets(component.getParent(), data.getTargets());
        if (component.getAttributes().containsKey(SecuredComponent.MARKER)) {
            for (UIComponent targetComponent : targets) {
                SecuredComponentData dataForTarget = new SecuredComponentData(data);
                dataForTarget.setTargetComponent(targetComponent);

                SecuredComponentHandler.setNoAccess(targetComponent, dataForTarget);
            }
        } else {
            for (UIComponent targetComponent : targets) {
                targetComponent.getAttributes().put(SecuredComponent.DATA, data);
            }
        }
    }
}
