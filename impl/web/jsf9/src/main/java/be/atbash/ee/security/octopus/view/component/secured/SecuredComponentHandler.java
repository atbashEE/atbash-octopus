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

import be.atbash.ee.security.octopus.view.component.OctopusComponentHandler;
import be.atbash.util.CDIUtils;
import be.atbash.util.JsfUtils;

import jakarta.faces.component.UIComponent;
import jakarta.faces.view.facelets.ComponentConfig;

/**
 * Component handler for the <code><sec:securedComponent/></code> JSF tag.
 */
public class SecuredComponentHandler extends OctopusComponentHandler {

    private OctopusHandlerHelper octopusHandlerHelper;

    /**
     * classic Constructor for a Component handler with a {@link ComponentConfig}.
     *
     * @param config The {@link ComponentConfig}
     */
    public SecuredComponentHandler(ComponentConfig config) {
        super(config);
    }

    @Override
    protected void handleComponentSecurity(UIComponent component, UIComponent parent) {
        // Initialize the helper which does the must of the work.
        checkServices();

        // Retrieve information about the tag.
        SecuredComponentData data = octopusHandlerHelper.gatherSecurityInfo(component, parent);

        if (JsfUtils.isRenderResponsePhase() && !data.hasAtRuntimeParameter()) {

            if (!octopusHandlerHelper.hasAccess(data)) {
                for (UIComponent targetComponent : data.getAllTargetComponents()) {
                    SecuredComponentData dataForTarget = new SecuredComponentData(data);
                    dataForTarget.setTargetComponent(targetComponent);
                    setNoAccess(targetComponent, dataForTarget);
                }
            }
        } else {
            for (UIComponent targetComponent : data.getAllTargetComponents()) {
                SecuredComponentData dataForTarget = new SecuredComponentData(data);
                dataForTarget.setTargetComponent(targetComponent);

                targetComponent.getAttributes().put(SecuredComponent.DATA, dataForTarget);
            }
        }
    }

    private void checkServices() {
        // Since ComponentHandler is not a CDI artifact, we instantiate it here lazily.
        if (octopusHandlerHelper == null) {
            octopusHandlerHelper = CDIUtils.retrieveInstance(OctopusHandlerHelper.class);
        }
    }

    public static void setNoAccess(UIComponent targetComponent, SecuredComponentData dataForTarget) {
        targetComponent.setRendered(false);
        targetComponent.getAttributes().put(SecuredComponent.MARKER, Boolean.TRUE);
        if (dataForTarget != null) {

            targetComponent.getAttributes().put(SecuredComponent.DATA, dataForTarget);
        }
    }

}
