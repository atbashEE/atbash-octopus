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

import javax.el.ValueExpression;
import javax.faces.component.UIComponentBase;
import javax.faces.view.facelets.FaceletContext;
import javax.faces.view.facelets.TagAttribute;
import java.util.HashMap;
import java.util.Map;

/**
 *
 */
class ComponentAroundTagHandler extends UIComponentBase {

    private static final String[] PERMISSION_LISTENER_ATTRIBUTES = new String[]{"voter", "permission", "role", "not", "combined", "for", "listener"};

    private Map<String, Object> attributes = new HashMap<>();
    private Map<String, ValueExpression> valueExpressions = new HashMap<>();

    ComponentAroundTagHandler(FaceletContext ctx, OctopusTagHandler tagHandler) {

        for (String attributeName : PERMISSION_LISTENER_ATTRIBUTES) {
            TagAttribute attribute = tagHandler.getAttributeCallback(attributeName);
            if (attribute != null) {
                String value = attribute.getValue();

                if (valueExpression(value)) {
                    if (!methodExpression(value)) {
                        valueExpressions.put(attributeName, attribute.getValueExpression(ctx, Object.class));
                    }
                } else {
                    attributes.put(attributeName, value);
                }
            }
        }
    }

    private boolean methodExpression(String value) {
        return value.endsWith(")}");
    }

    private boolean valueExpression(String value) {
        return value.contains("#{");
    }

    @Override
    public String getFamily() {
        return "Fake";
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public ValueExpression getValueExpression(String s) {
        return valueExpressions.get(s);
    }
}
