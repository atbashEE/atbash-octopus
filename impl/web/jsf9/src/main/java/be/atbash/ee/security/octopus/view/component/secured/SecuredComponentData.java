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

import be.atbash.ee.security.octopus.authz.Combined;

import jakarta.faces.component.UIComponent;
import java.util.List;

/**
 *
 */
public class SecuredComponentData {

    private final String[] voters;

    private final boolean not;

    private final Combined combined;

    private final SecuredComponentDataParameter[] parameters;

    private final String targets;

    private UIComponent targetComponent;

    private List<UIComponent> allTargetComponents;

    /**
     * Required for restoring the state
     */
    public SecuredComponentData() {
        this("", false, Combined.OR, null, null);
    }

    public SecuredComponentData(String voter, boolean notValue, Combined combined,
                                SecuredComponentDataParameter[] parameters, String targets) {
        voters = voter.split(",");
        not = notValue;
        this.combined = combined;
        this.parameters = parameters;
        this.targets = targets;
    }

    public SecuredComponentData(SecuredComponentData securedComponentData) {
        voters = securedComponentData.getVoters();
        not = securedComponentData.isNot();
        combined = securedComponentData.getCombined();
        parameters = securedComponentData.getParameters();
        targets = securedComponentData.getTargets();
        // TODO Verify the allTargetComponents property
    }

    public void setTargetComponent(UIComponent someTargetComponent) {
        targetComponent = someTargetComponent;
    }

    public UIComponent getTargetComponent() {
        return targetComponent;
    }

    public List<UIComponent> getAllTargetComponents() {
        return allTargetComponents;
    }

    public void setAllTargetComponents(List<UIComponent> allTargetComponents) {
        this.allTargetComponents = allTargetComponents;
        if (!allTargetComponents.isEmpty()) {
            setTargetComponent(allTargetComponents.get(0));
        }
    }

    public String getTargets() {
        return targets;
    }

    public String[] getVoters() {
        return voters;
    }

    public boolean isNot() {
        return not;
    }

    public Combined getCombined() {
        return combined;
    }

    public SecuredComponentDataParameter[] getParameters() {
        return parameters;
    }

    public boolean hasAtRuntimeParameter() {
        boolean result = false;
        for (SecuredComponentDataParameter parameter : parameters) {
            if (parameter.isAtRuntime()) {
                result = true;
                break;
            }
        }
        return result;
    }
}
