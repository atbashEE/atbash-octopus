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

import be.atbash.ee.security.octopus.subview.model.JWKSetData;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuBar;
import javafx.scene.control.MenuItem;
import javafx.scene.control.SeparatorMenuItem;
import javafx.scene.layout.BorderPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;

/**
 *
 */

public class ApplicationMenu extends SubView {

    private JWKSetData jwkSetData = new JWKSetData();

    public ApplicationMenu(Stage primaryStage, BorderPane rootPane) {
        super(primaryStage, rootPane);
    }

    public void initialize() {
        MenuBar menuBar = new MenuBar();
        // Make same width as the stage
        menuBar.prefWidthProperty().bind(primaryStage.widthProperty());
        rootPane.setTop(menuBar);

        // File menu - new, save, exit
        Menu fileMenu = new Menu("File");
        MenuItem newMenuItem = createMenuItem("New", actionEvent -> this.onNewFile());

        MenuItem openMenuItem = createMenuItem("Open", actionEvent -> this.onOpenFile());

        MenuItem saveMenuItem = createMenuItem("Save", actionEvent -> this.onSaveFile());
        saveMenuItem.disableProperty().bind(jwkSetData.changedProperty().not());

        MenuItem exitMenuItem = createMenuItem("Exit", actionEvent -> Platform.exit());

        fileMenu.getItems().addAll(newMenuItem, openMenuItem, saveMenuItem,
                new SeparatorMenuItem(), exitMenuItem);

        menuBar.getMenus().addAll(fileMenu);
    }

    private MenuItem createMenuItem(String aNew, EventHandler<ActionEvent> actionEventEventHandler) {
        MenuItem newMenuItem = new MenuItem(aNew);
        newMenuItem.setOnAction(actionEventEventHandler);
        return newMenuItem;
    }

    private void onNewFile() {
        jwkSetData.onNewFile();
        new JWKView(primaryStage, rootPane, jwkSetData).initialize();
    }

    private void onOpenFile() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open JWK File");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("JWK Files", "*.jwk"));

        File selectedFile = fileChooser.showOpenDialog(primaryStage);
        if (selectedFile != null) {
            jwkSetData.onOpenFile(selectedFile);
            new JWKView(primaryStage, rootPane, jwkSetData).initialize();
        }

    }

    private void onSaveFile() {
        if (!jwkSetData.hasFileName()) {
            File selectedFile = askFileName();
            jwkSetData.onSaveFile(selectedFile);
        } else {
            jwkSetData.onSaveFile();
        }

    }

    private File askFileName() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Save JWK File");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("JWK result (*.jwk)", "*.jwk"));
        fileChooser.setInitialFileName("*.jwk");

        File result = fileChooser.showSaveDialog(primaryStage);
        if (result != null) {
            if (!result.getName().endsWith(".jwk")) {
                // FIXME
                throw new RuntimeException(result.getName() + " has no valid JWK-extension.");
            }
        }
        return result;
    }
}


