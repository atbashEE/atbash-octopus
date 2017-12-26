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

import be.atbash.ee.security.octopus.subview.model.JWKItem;
import be.atbash.ee.security.octopus.subview.model.JWKSetData;
import javafx.beans.binding.Bindings;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.geometry.Insets;
import javafx.scene.control.*;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.scene.text.Text;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.util.Optional;

import static be.atbash.ee.security.octopus.ScreenArtifacts.*;

/**
 *
 */

public class JWKView extends SubView {

    private final JWKSetData jwkSetData;

    private TableView<JWKItem> tableView;
    private HBox buttonRow;

    public JWKView(Stage primaryStage, BorderPane rootPane, JWKSetData jwkSetData) {
        super(primaryStage, rootPane);
        this.jwkSetData = jwkSetData;
    }

    @Override
    public void initialize() {
        defineTable();
        defineTableButtons();

        defineSubView();
    }

    private void defineTable() {
        tableView = new TableView<>();

        TableColumn<JWKItem, String> idCol = new TableColumn<>("ID");
        TableColumn<JWKItem, String> typeCol = new TableColumn<>("Type");
        TableColumn<JWKItem, Boolean> privateCol = new TableColumn<>("Private");
        TableColumn<JWKItem, String> keyUseCol = new TableColumn<>("Key Usage");

        idCol.setCellValueFactory(new PropertyValueFactory<>("kid"));
        typeCol.setCellValueFactory(new PropertyValueFactory<>("keyType"));
        privateCol.setCellValueFactory(new PropertyValueFactory<>("privatePart"));
        keyUseCol.setCellValueFactory(new PropertyValueFactory<>("keyUse"));

        tableView.getColumns().addAll(idCol, typeCol, privateCol, keyUseCol);
        ObservableList<JWKItem> list = getItemList();
        tableView.setItems(list);

    }

    private void defineSubView() {
        VBox mainView = new VBox();
        mainView.setPadding(new Insets(10, 10, 10, 10));

        Text title = new Text("JWK File contents");
        title.setFont(viewTitleFont);

        mainView.getChildren().addAll(title, buttonRow, tableView);

        rootPane.setCenter(mainView);
    }

    private void defineTableButtons() {
        Button addButton = new Button("Add", addIconView);
        addButton.setOnAction(actionEvent -> new NewJWKView(primaryStage, rootPane, jwkSetData).initialize());

        Button removeButton = new Button("Remove", removeIconView);
        removeButton.setOnAction(actionEvent -> onRemove(tableView));
        removeButton.disableProperty().bind(Bindings.isEmpty(tableView.getSelectionModel().getSelectedItems()));

        Button importButton = new Button("Import", importIconView);
        importButton.setOnAction(actionEvent -> onImport());

        buttonRow = new HBox(30);  // Buttons
        buttonRow.setPadding(new Insets(10, 10, 10, 10));
        buttonRow.getChildren().addAll(addButton, removeButton, importButton);

    }

    private void onRemove(TableView<JWKItem> table) {
        JWKItem jwkItem = table.getSelectionModel().getSelectedItem();
        if (jwkItem == null) {
            return;
        }
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle("Confirmation Dialog");
        alert.setHeaderText("Confirm delete");
        alert.setContentText(String.format("Are you sure you want to delete key with id '%s'?", jwkItem.getKid()));

        Optional<ButtonType> result = alert.showAndWait();
        if (result.isPresent()) {
            if (ButtonType.OK.equals(result.get())) {
                jwkSetData.removeKey(jwkItem.getKid());
            }
        }
    }

    private void onImport() {
        File importFile = chooseFile();
        if (importFile != null) {
            new ImportJWKView(primaryStage, rootPane, jwkSetData, importFile).initialize();
        }
    }

    private File chooseFile() {
        // FIXME Duplicate with ApplicationMenu onOpenFile
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Open JWK File");
        fileChooser.getExtensionFilters().addAll(
                new FileChooser.ExtensionFilter("JWK Files", "*.jwk"));

        return fileChooser.showOpenDialog(primaryStage);

    }

    private ObservableList<JWKItem> getItemList() {

        return FXCollections.observableArrayList(jwkSetData.getItems());
    }

}
