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

import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.scene.control.Alert;
import javafx.util.Duration;

/**
 *
 */

public class InfoDialog {

    private String message;

    public InfoDialog(String message) {
        this.message = message;
    }

    public void showDialog() {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle("Feedback Dialog");
        alert.setHeaderText("Confirmation of action");
        alert.setContentText(message);

        alert.show();
        Timeline idlestage = new Timeline(new KeyFrame(Duration.seconds(3), event -> alert.hide()));
        idlestage.setCycleCount(1);
        idlestage.play();
    }
}
