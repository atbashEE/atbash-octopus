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
import be.atbash.ee.security.octopus.javafx.LoginFXMLView;
import be.atbash.ee.security.octopus.javafx.SecureFXMLApplication;
import com.airhacks.afterburner.views.FXMLView;

/**
 * Manages control flow for logins.
 */
public class LoginManager {
    private LoginFXMLView loginView;
    private FXMLView firstView;

    /**
     * Defines the view shown at login and first view after successful login.
     *
     * @param loginView
     * @param firstView
     */
    public LoginManager(LoginFXMLView loginView, FXMLView firstView) {
        this.loginView = loginView;
        this.firstView = firstView;
    }

    /**
     * Callback method invoked to notify that a user has been authenticated.
     * Will show the main application screen.
     */
    public void authenticated() {
        loginView.resetView();
        SecureFXMLApplication.showPage(firstView);
    }

    /**
     * Callback method invoked to notify that a user has logged out of the main application.
     * Will show the login application screen.
     */
    public void logout() {
        SecurityUtils.getSubject().logout();
        SecureFXMLApplication.showPage(loginView);
    }

}