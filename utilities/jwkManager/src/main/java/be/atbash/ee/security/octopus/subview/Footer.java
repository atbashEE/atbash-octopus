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

import be.atbash.util.version.VersionReader;
import javafx.geometry.Insets;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.text.Text;
import javafx.stage.Stage;

import static be.atbash.ee.security.octopus.ScreenArtifacts.versionFont;

/**
 *
 */

public class Footer extends SubView {

    public Footer(Stage primaryStage, BorderPane rootPane) {
        super(primaryStage, rootPane);
    }

    @Override
    public void initialize() {

        VersionReader versionReader = new VersionReader();
        versionReader.readInfo("jwk-util");
        Text version = new Text(String.format("Version %s (%s)", versionReader.getReleaseVersion(), versionReader.getBuildTime()));

        version.setFont(versionFont);

        HBox bottom = new HBox();
        Region spacer = new Region();
        HBox.setHgrow(spacer, Priority.ALWAYS);
        bottom.getChildren().addAll(spacer, version);
        bottom.setPadding(new Insets(10, 10, 5, 0));

        rootPane.setBottom(bottom);

    }
}
