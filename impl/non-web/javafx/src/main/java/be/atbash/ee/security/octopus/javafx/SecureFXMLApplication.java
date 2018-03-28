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

import be.atbash.ee.security.octopus.javafx.view.LoginManager;
import be.atbash.ee.security.octopus.javafx.view.LoginPresenter;
import be.atbash.ee.security.octopus.javafx.view.MainPresenter;
import be.atbash.util.exception.AtbashUnexpectedException;
import com.airhacks.afterburner.views.FXMLView;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.layout.Pane;
import javafx.scene.layout.StackPane;
import javafx.stage.Stage;

import java.io.IOException;

public class SecureFXMLApplication {

    private static StackPane vistaHolder;
    private static Stage stage;
    private static LoginManager loginManager;

    public static void start(Stage stage, LoginFXMLView loginView, FXMLView firstView) {

        try {
            Scene scene = new Scene(loadMainPane());
            loginManager = new LoginManager(loginView, firstView);

            LoginPresenter controller = (LoginPresenter) loginView.getPresenter();
            controller.initManager(loginManager, loginView.getAuthenticationExceptionCallback());

            stage.setScene(scene);

            stage.show();

        } catch (IOException e) {
            throw new AtbashUnexpectedException(e);
        }

        SecureFXMLApplication.stage = stage;
        showPage(loginView);

    }

    /**
     * Loads the main fxml layout.
     * Sets up the vista switching VistaNavigator.
     * Loads the first vista into the fxml layout.
     *
     * @return the loaded pane.
     * @throws IOException if the pane could not be loaded.
     */
    private static Pane loadMainPane() throws IOException {
        FXMLLoader loader = new FXMLLoader();

        Pane mainPane = loader.load(
                SecureFXMLApplication.class.getResourceAsStream(
                        "main.fxml"
                )
        );

        MainPresenter mainPresenter = loader.getController();
        vistaHolder = mainPresenter.getVistaHolder();

        return mainPane;
    }

    public static void showPage(FXMLView view) {
        Parent parent = view.getView();
        vistaHolder.getChildren().setAll(parent);

        if (parent instanceof Pane) {
            Pane pane = (Pane) parent;
            stage.setWidth(pane.getPrefWidth());
            stage.setHeight(pane.getPrefHeight());
        }
    }

    /**
     * Logout the user and shows the login view again.
     */
    public static void logout() {
        loginManager.logout();
    }
}
