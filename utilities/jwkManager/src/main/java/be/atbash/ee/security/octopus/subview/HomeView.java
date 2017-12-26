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
package be.atbash.ee.security.octopus.subview;

import javafx.scene.layout.BorderPane;
import javafx.scene.paint.Color;
import javafx.scene.text.Text;
import javafx.stage.Stage;

import static be.atbash.ee.security.octopus.ScreenArtifacts.titleFont;

/**
 *
 */

public class HomeView extends SubView {

    public HomeView(Stage primaryStage, BorderPane rootPane) {
        super(primaryStage, rootPane);
    }

    public void initialize() {
        Text title = new Text("Atbash JWK Manager ");
        title.setFont(titleFont);
        title.setFill(Color.DARKGOLDENROD);

        rootPane.setCenter(title);

    }
}
