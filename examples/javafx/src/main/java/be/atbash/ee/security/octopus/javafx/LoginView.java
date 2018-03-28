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

import be.atbash.ee.security.octopus.authc.AuthenticationException;
import javafx.scene.Parent;
import javafx.scene.control.TextField;
import javafx.scene.control.Tooltip;

import java.util.function.Consumer;

/**
 * FXML View for login capable of handling  AuthenticationException. See loginView.fxml in same directory in resource directory.
 */
public class LoginView extends LoginFXMLView {

    private Tooltip tooltip = new Tooltip();

    private TextField userField;

    @Override
    public Parent getView() {
        Parent result = super.getView();

        userField = (TextField) result.lookup("#user");

        return result;
    }

    @Override
    public Consumer<AuthenticationException> getAuthenticationExceptionCallback() {
        return this::handleLoginError;
    }

    @Override
    public void resetView() {
        tooltip.hide();
        userField.setStyle("");
    }

    private void handleLoginError(AuthenticationException e) {
        userField.setStyle("-fx-border-color: red");
        tooltip.setText("Unknown user name - password combination");
        tooltip.show(userField, //
                // popup tooltip on the right, you can adjust these values for different positions
                userField.getScene().getWindow().getX() + userField.getLayoutX() + userField.getWidth() + 10, //
                userField.getScene().getWindow().getY() + userField.getLayoutY() + userField.getHeight());

    }
}
