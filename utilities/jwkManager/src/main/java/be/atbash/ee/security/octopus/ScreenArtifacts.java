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

import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.text.Font;

/**
 *
 */

public class ScreenArtifacts {

    public static Font titleFont;
    public static Font viewTitleFont;
    public static Font versionFont;
    public static ImageView addIconView;
    public static ImageView removeIconView;
    public static ImageView importIconView;

    static {
        titleFont = Font.font("Helvetica", 50);
        viewTitleFont = Font.font("Helvetica", 26);
        versionFont = Font.font("System", 11);
        addIconView = loadIconView("/add-icon.png");
        removeIconView = loadIconView("/remove-icon.png");
        importIconView = loadIconView("/import-icon.png");
    }

    private static ImageView loadIconView(String iconFileName) {
        return new ImageView(
                new Image(ScreenArtifacts.class.getResourceAsStream(iconFileName)));
    }

}
