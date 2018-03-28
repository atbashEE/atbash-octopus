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
package be.atbash.ee.security.octopus.javafx.view;

import be.atbash.ee.security.octopus.SecurityUtils;
import be.atbash.ee.security.octopus.authc.AuthenticationException;
import be.atbash.ee.security.octopus.javafx.authc.UsernamePasswordToken;
import be.atbash.ee.security.octopus.subject.Subject;
import be.atbash.ee.security.octopus.token.AuthenticationToken;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextField;

import java.util.function.Consumer;

/**
 * Controls the login screen
 */
public class LoginPresenter {
    @FXML
    private TextField user;
    @FXML
    private TextField password;
    @FXML
    private Button loginButton;

    public void initManager(final LoginManager loginManager, Consumer<AuthenticationException> authenticationExceptionCallback) {
        loginButton.setOnAction(event -> {
            try {
                String sessionID = authorize();
                if (sessionID != null) {
                    user.setText("");
                    password.setText("");
                    loginManager.authenticated();

                }
            } catch (AuthenticationException e) {
                authenticationExceptionCallback.accept(e);
            }
        });
    }

    /**
     * Check authorization credentials.
     * <p>
     * If accepted, return a sessionID for the authorized session
     * otherwise, return null.
     */
    private String authorize() {

        AuthenticationToken token = new UsernamePasswordToken(user.getText(), password.getText());
        SecurityUtils.getSubject().login(token);

        String result = null;
        Subject subject = SecurityUtils.getSubject();
        if (subject.isAuthenticated()) {
            result = subject.getPrincipal().toString();
        }

        return result;
    }

}