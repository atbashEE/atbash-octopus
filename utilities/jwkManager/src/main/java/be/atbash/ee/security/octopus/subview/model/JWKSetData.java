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
package be.atbash.ee.security.octopus.subview.model;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.SimpleBooleanProperty;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Scanner;

/**
 *
 */

public class JWKSetData {

    private JWKSet jwkSet;
    private File currentFile;
    private BooleanProperty changed;

    public JWKSetData() {
        changed = new SimpleBooleanProperty(false);
    }

    public void onNewFile() {
        currentFile = null;
        jwkSet = new JWKSet();
        changed.setValue(true);
    }

    public void onOpenFile(File selectedFile) {
        jwkSet = readFile(selectedFile);
        currentFile = selectedFile;
        changed.setValue(false);
    }

    private JWKSet readFile(File selectedFile) {
        JWKSet result = null;
        try {
            try (FileInputStream inputStream = new FileInputStream(selectedFile)) {
                String content = new Scanner(inputStream).useDelimiter("\\Z").next();
                result = JWKSet.parse(content);
            }
        } catch (IOException e) {
            // Should never happen
        } catch (ParseException e) {
            e.printStackTrace();
            // FIXME
        }
        return result;
    }

    public List<JWKItem> getItems() {
        List<JWKItem> result = new ArrayList<>();
        for (JWK jwk : jwkSet.getKeys()) {
            JWKItem item = new JWKItem();
            item.setKid(jwk.getKeyID());
            item.setKeyType(jwk.getKeyType().getValue());
            item.setPrivatePart(jwk.isPrivate());
            if (jwk.getKeyUse() != null) {
                item.setKeyUse(jwk.getKeyUse().identifier());
            }
            result.add(item);
        }
        return result;
    }

    public void add(JWK key) {
        // jwkSet.getKeys() -> immutable list
        List<JWK> temp = new ArrayList<>(jwkSet.getKeys());
        temp.add(key);
        jwkSet = new JWKSet(temp);
        changed.setValue(true);
    }

    public JWK getKey(String id) {
        return jwkSet.getKeyByKeyId(id);
    }

    public void onSaveFile(File selectedFile) {
        currentFile = selectedFile;
        onSaveFile();
    }

    public void onSaveFile() {
        String content = jwkSet.toJSONObject(false).toString();
        try {
            try (FileWriter output = new FileWriter(currentFile)) {
                output.write(content);
                output.flush();
            }
        } catch (IOException e) {
            e.printStackTrace();
            // FIXME
        }
    }

    public void removeKey(String kid) {
        Iterator<JWK> iterator = jwkSet.getKeys().iterator();
        while (iterator.hasNext()) {
            JWK jwk = iterator.next();
            if (jwk.getKeyID().equals(kid)) {
                iterator.remove();
                changed.setValue(true);
                break;
            }
        }
    }

    public BooleanProperty changedProperty() {
        return changed;
    }

    public boolean hasFileName() {
        return currentFile != null;
    }

}
