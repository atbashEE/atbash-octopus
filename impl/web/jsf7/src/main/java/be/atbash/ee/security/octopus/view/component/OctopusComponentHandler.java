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
package be.atbash.ee.security.octopus.view.component;

import javax.faces.component.UIComponent;
import javax.faces.view.facelets.ComponentConfig;
import javax.faces.view.facelets.ComponentHandler;
import javax.faces.view.facelets.FaceletContext;
import javax.faces.view.facelets.FaceletException;

/**
 *
 */
public abstract class OctopusComponentHandler extends ComponentHandler {

    private static final String BODY_TYPE = "javax.faces.Body";

    public OctopusComponentHandler(ComponentConfig config) {
        super(config);
    }

    @Override
    public final void onComponentPopulated(FaceletContext ctx, UIComponent component, UIComponent parent) {
        super.onComponentPopulated(ctx, component, parent);

        if (BODY_TYPE.equals(parent.getRendererType())) {
            securityOnBody();
        }

        handleComponentSecurity(component, parent);
    }

    protected abstract void handleComponentSecurity(UIComponent component, UIComponent parent);

    private void securityOnBody() {
        throw new FaceletException("Octopus Security tag placed on <h:body> : " + tag.toString());
    }

}
