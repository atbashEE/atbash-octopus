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
package be.atbash.json.writer;

import be.atbash.json.JSONUtil;
import net.minidev.asm.Accessor;
import net.minidev.asm.BeansAccess;

import java.io.IOException;
import java.util.HashMap;

/**
 * Atbash added file
 */

public abstract class CustomBeanMapper<T> extends CustomMapper<T> {

    private final BeansAccess<T> ba;
    private final HashMap<String, Accessor> index;

    /**
     * Reader can be link to the JsonReader Base
     *
     * @param base
     * @param type
     */
    public CustomBeanMapper(JSONReader base, Class<T> type) {
        super(base, type);
        this.ba = BeansAccess.get(clz, JSONUtil.JSON_SMART_FIELD_FILTER);
        this.index = ba.getMap();
    }

    public abstract void setCustomValue(T current, String key, Object value);

    @Override
    public void setValue(Object current, String key, Object value) throws IOException {
        if (ba.getIndex(key) == -1) {
            setCustomValue((T) current, key, value);
        } else {
            ba.set((T) current, key, value);
        }
    }
}

