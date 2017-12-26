/*
 * Copyright 2014-2017 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.security.octopus;

import be.atbash.ee.security.octopus.subview.ApplicationMenu;
import be.atbash.ee.security.octopus.subview.Footer;
import be.atbash.ee.security.octopus.subview.HomeView;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.layout.BorderPane;
import javafx.scene.paint.Color;
import javafx.stage.Stage;

/**
 *
 */

public class JWKManagerUI extends Application {

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage primaryStage) {
        primaryStage.setTitle("Atbash JWK Manager");

        BorderPane root = new BorderPane();

        Scene scene = new Scene(root, 600, 350, Color.WHITE);
        primaryStage.setMinWidth(500);
        primaryStage.setMinHeight(300);

        new ApplicationMenu(primaryStage, root).initialize();
        new HomeView(primaryStage, root).initialize();
        new Footer(primaryStage, root).initialize();

        root.prefHeightProperty().bind(scene.heightProperty());
        root.prefWidthProperty().bind(scene.widthProperty());

        primaryStage.setScene(scene);
        primaryStage.show();
    }

}