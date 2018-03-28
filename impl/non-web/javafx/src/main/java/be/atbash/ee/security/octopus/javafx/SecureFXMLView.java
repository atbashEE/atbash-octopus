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
package be.atbash.ee.security.octopus.javafx;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authz.checks.AnnotationCheckFactory;
import be.atbash.ee.security.octopus.authz.checks.SecurityCheckData;
import be.atbash.ee.security.octopus.authz.checks.SecurityCheckInfo;
import be.atbash.ee.security.octopus.context.internal.OctopusInvocationContext;
import be.atbash.ee.security.octopus.interceptor.CustomAccessDecisionVoterContext;
import be.atbash.ee.security.octopus.javafx.authz.checks.JavaFXSecurityCheckDataFactory;
import be.atbash.ee.security.octopus.javafx.authz.tag.RequiresPermissions;
import com.airhacks.afterburner.views.FXMLView;
import javafx.scene.Node;
import javafx.scene.Parent;

public class SecureFXMLView extends FXMLView {

    private static AnnotationCheckFactory annotationCheckFactory;

    @Override
    public Parent getView() {
        checkDependencies();
        Parent view = super.getView();
        setNodeVisibility(view);
        return view;
    }

    private void checkDependencies() {
        if (annotationCheckFactory == null) {
            annotationCheckFactory = new AnnotationCheckFactory();
            annotationCheckFactory.initChecks();
        }
    }

    private void setNodeVisibility(Node node) {
        Object userData = node.getUserData();

        if (userData instanceof RequiresPermissions) {
            SecurityCheckData securityCheckData = JavaFXSecurityCheckDataFactory.defineSecurityCheckData((RequiresPermissions) userData);

            OctopusInvocationContext invocationContext = new OctopusInvocationContext(node, null);
            CustomAccessDecisionVoterContext context = new CustomAccessDecisionVoterContext(invocationContext);

            SecurityCheckInfo checkInfo = annotationCheckFactory.getCheck(securityCheckData).performCheck(SecurityUtils.getSubject(), context, securityCheckData);

            if (!checkInfo.isAccessAllowed()) {
                node.setVisible(false);
            } else {
                node.setVisible(true);
            }
        }

        if (node instanceof Parent) {
            Parent parent = (Parent) node;
            for (Node child : parent.getChildrenUnmodifiable()) {
                setNodeVisibility(child);
            }
        }

    }
}
