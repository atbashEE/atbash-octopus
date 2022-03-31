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
import be.atbash.ee.security.octopus.config.names.VoterNameFactory;
import be.atbash.ee.security.octopus.view.component.OctopusComponentUsageException;
import be.atbash.ee.security.octopus.view.component.service.ComponentAuthorizationService;
import be.atbash.util.ComponentCallback;
import be.atbash.util.ComponentUtils;
import be.atbash.util.StringUtils;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.faces.component.UIComponent;
import jakarta.faces.component.UIParameter;
import jakarta.faces.context.FacesContext;
import jakarta.faces.event.PreRenderViewEvent;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.List;

/**
 *
 */
@ApplicationScoped
public class OctopusHandlerHelper {

    @Inject
    private ComponentAuthorizationService componentAuthorizationService;

    @Inject
    private VoterNameFactory voterNameFactory;

    public SecuredComponentData gatherSecurityInfo(UIComponent component, UIComponent parent) {
        String voter = getVoterName(component);
        if (StringUtils.isEmpty(voter)) {
            throw new OctopusComponentUsageException("securedComponent needs one of the properties voter, permission or role specified");
        }

        Boolean not = ComponentUtils.getAttributeValue(component, "not", Boolean.class);
        if (not == null) {
            not = Boolean.FALSE;
        }
        Combined combined = Combined.OR;
        Boolean value = ComponentUtils.getAttributeValue(component, "combined", Boolean.class);
        if (value != null) {
            combined = value ? Combined.AND : Combined.OR;
        }
        String target = ComponentUtils.getAttributeValue(component, "for", String.class);

        CollectAndRelocateInfoOnTargets callback = new CollectAndRelocateInfoOnTargets(component);
        ComponentUtils.processTargets(parent, target, callback);
        List<UIComponent> targets = callback.getTargets();

        SecuredComponentDataParameter[] parameters = findParameters(component);

        SecuredComponentData result = new SecuredComponentData(voter, not, combined, parameters, target);

        result.setAllTargetComponents(targets);

        return result;
    }

    private String getVoterName(UIComponent component) {
        StringBuilder result = new StringBuilder();
        String voter = ComponentUtils.getAttributeValue(component, "voter", String.class);
        appendVoterNames(result, voter);
        String permission = ComponentUtils.getAttributeValue(component, "permission", String.class);
        if (permission != null && permission.length() != 0) {
            voter = voterNameFactory.generatePermissionBeanName(permission);
            appendVoterNames(result, voter);
        }
        String role = ComponentUtils.getAttributeValue(component, "role", String.class);
        if (role != null && role.length() != 0) {
            voter = voterNameFactory.generateRoleBeanName(role);
            appendVoterNames(result, voter);
        }
        return result.toString();
    }

    private void appendVoterNames(StringBuilder result, String voter) {
        if (voter != null && !voter.trim().isEmpty()) {
            if (result.length() > 0) {
                result.append(',');
            }
            result.append(voter);
        }
    }

    private SecuredComponentDataParameter[] findParameters(UIComponent c) {
        // TODO Write some examples about this usage
        List<SecuredComponentDataParameter> result = new ArrayList<>();
        for (UIComponent child : c.getChildren()) {
            if (child instanceof UIParameter) {
                UIParameter uiParameter = (UIParameter) child;
                result.add(new SecuredComponentDataParameter(uiParameter.getValue()));
            }
            if (child instanceof SecuredComponentParameter) {
                SecuredComponentParameter parameter = (SecuredComponentParameter) child;
                result.add(new SecuredComponentDataParameter(parameter.getValueExpression("value")
                        .getExpressionString(), true));
            }
        }

        return result.toArray(new SecuredComponentDataParameter[]{});
    }

    public boolean hasAccess(SecuredComponentData data) {
        return componentAuthorizationService.hasAccess(data);
    }

    public static class CollectAndRelocateInfoOnTargets implements ComponentCallback {

        private UIComponent component;
        private List<UIComponent> targets;

        public CollectAndRelocateInfoOnTargets(UIComponent component) {
            this.component = component;
            targets = new ArrayList<>();
        }

        @Override
        public void handle(UIComponent uiComponent, boolean customComponent) {
            if (customComponent) {
                FacesContext.getCurrentInstance().getViewRoot().subscribeToViewEvent(PreRenderViewEvent
                        .class, new RelocateSecurityInformationEventListener(uiComponent));
                targets.add(component);

            } else {
                targets.add(uiComponent);
            }
        }

        public List<UIComponent> getTargets() {
            return targets;
        }
    }
}
