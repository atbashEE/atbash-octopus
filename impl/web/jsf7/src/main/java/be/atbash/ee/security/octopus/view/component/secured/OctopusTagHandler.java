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

import be.atbash.util.CDIUtils;

import javax.faces.component.UIComponent;
import javax.faces.view.facelets.FaceletContext;
import javax.faces.view.facelets.TagAttribute;
import javax.faces.view.facelets.TagConfig;
import javax.faces.view.facelets.TagHandler;
import java.io.IOException;

/**
 *
 */

public abstract class OctopusTagHandler extends TagHandler {

    protected OctopusHandlerHelper octopusHandlerHelper;

    public OctopusTagHandler(TagConfig config) {
        super(config);
    }

    @Override
    public void apply(FaceletContext ctx, UIComponent parent) throws IOException {

        checkServices();

        SecuredComponentData data = octopusHandlerHelper.gatherSecurityInfo(new ComponentAroundTagHandler(ctx, this), parent);

        handleSecurity(ctx, parent, data);

    }

    abstract void handleSecurity(FaceletContext ctx, UIComponent parent, SecuredComponentData securedComponentData);

    TagAttribute getAttributeCallback(String name) {
        return getAttribute(name);
    }

    private void checkServices() {
        if (octopusHandlerHelper == null) {
            octopusHandlerHelper = CDIUtils.retrieveInstance(OctopusHandlerHelper.class);
        }
    }

}