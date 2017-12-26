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

import be.atbash.ee.security.octopus.jwk.RSAKeyFactory;
import be.atbash.ee.security.octopus.subview.model.JWKSetData;
import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.stage.Stage;

import java.util.UUID;

/**
 *
 */

public class NewJWKView extends SubView {

    private final JWKSetData jwkSetData;

    private StringProperty id = new SimpleStringProperty();
    private StringProperty keyType = new SimpleStringProperty();
    private StringProperty keySize = new SimpleStringProperty();

    protected NewJWKView(Stage primaryStage, BorderPane rootPane, JWKSetData jwkSetData) {
        super(primaryStage, rootPane);
        this.jwkSetData = jwkSetData;
    }

    @Override
    public void initialize() {
        GridPane grid = new GridPane();
        grid.setAlignment(Pos.CENTER);
        grid.setHgap(10);
        grid.setVgap(10);
        grid.setPadding(new Insets(25, 25, 25, 25));

        Label kidLabel = new Label("Id :");
        grid.add(kidLabel, 0, 0);

        HBox idPane = new HBox(10);
        TextField kidField = new TextField();
        kidField.textProperty().bindBidirectional(id);

        Button kidButton = new Button("id");
        kidButton.setOnAction(eventAction -> id.setValue(UUID.randomUUID().toString()));

        idPane.getChildren().addAll(kidField, kidButton);
        grid.add(idPane, 1, 0);

        Label typeLabel = new Label("Type :");
        grid.add(typeLabel, 0, 1);

        ComboBox keyTypeComboBox = new ComboBox();
        keyTypeComboBox.getItems().addAll(
                "RSA"
        );
        keyTypeComboBox.valueProperty().bindBidirectional(keyType);
        grid.add(keyTypeComboBox, 1, 1);

        Label lengthLabel = new Label("Length :");
        grid.add(lengthLabel, 0, 2);

        ComboBox keyLengthComboBox = new ComboBox();
        keyLengthComboBox.getItems().addAll(
                "2048",
                "3072",
                "4096"
        );
        keyLengthComboBox.valueProperty().bindBidirectional(keySize);
        grid.add(keyLengthComboBox, 1, 2);

        HBox buttonPane = new HBox(10);
        Button saveButton = new Button("Apply");
        saveButton.setOnAction(actionEvent -> this.createKey());

        Button cancelButton = new Button("Cancel");
        cancelButton.setOnAction(actionEvent -> new JWKView(primaryStage, rootPane, jwkSetData).initialize());

        buttonPane.getChildren().addAll(cancelButton, saveButton);

        grid.add(buttonPane, 1, 3);

        rootPane.setCenter(grid);
    }

    private void createKey() {
        RSAKeyFactory keyFactory = new RSAKeyFactory();
        // FIXME Not only RSA and Signature
        RSAKey rsaKey = keyFactory.makeRSA(Integer.valueOf(keySize.getValue()), KeyUse.SIGNATURE, new Algorithm("PS512"), id.getValue());
        jwkSetData.add(rsaKey);

        new JWKView(primaryStage, rootPane, jwkSetData).initialize();
    }
}
