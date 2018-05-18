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
package be.atbash.ee.security.octopus.subview;

import be.atbash.ee.security.octopus.keys.AtbashKey;
import be.atbash.ee.security.octopus.keys.generator.KeyGenerator;
import be.atbash.ee.security.octopus.keys.generator.RSAGenerationParameters;
import be.atbash.ee.security.octopus.keys.selector.AsymmetricPart;
import be.atbash.ee.security.octopus.keys.selector.filter.AsymmetricPartKeyFilter;
import be.atbash.ee.security.octopus.subview.model.JWKSetData;
import be.atbash.util.exception.AtbashUnexpectedException;
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

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
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

        RSAGenerationParameters generationParameters = new RSAGenerationParameters.RSAGenerationParametersBuilder()
                .withKeyId(id.getValue())
                .withKeySize(Integer.valueOf(keySize.getValue()))
                .build();
        KeyGenerator generator = new KeyGenerator();
        List<AtbashKey> keys = generator.generateKeys(generationParameters);

        // FIXME Converter of AtbashKey to JWK into jwt-support module
        RSAKey rsaKey = new RSAKey.Builder(getPublicKey(keys)).keyID(id.getValue())
                .privateKey(getPrivateKey(keys))
                .build();
        jwkSetData.add(rsaKey);

        new JWKView(primaryStage, rootPane, jwkSetData).initialize();
    }

    private RSAPublicKey getPublicKey(List<AtbashKey> keys) {
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PUBLIC).filter(keys);
        if (publicKeys.size() != 1) {
            throw new AtbashUnexpectedException("We should always find a Public RSA key");
        }
        return (RSAPublicKey) publicKeys.get(0).getKey();
    }

    private RSAPrivateKey getPrivateKey(List<AtbashKey> keys) {
        List<AtbashKey> publicKeys = new AsymmetricPartKeyFilter(AsymmetricPart.PRIVATE).filter(keys);
        if (publicKeys.size() != 1) {
            throw new AtbashUnexpectedException("We should always find a private RSA key");
        }
        return (RSAPrivateKey) publicKeys.get(0).getKey();
    }
}
