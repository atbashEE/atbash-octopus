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

import be.atbash.util.reflection.ClassUtils;

/**
 * Atbash added file
 */

public abstract class CustomMapper<T> extends Mapper<T> {

    protected final Class<T> clz;

    /**
     * Reader can be link to the JsonReader Base
     *
     * @param base
     * @param type
     */
    public CustomMapper(JSONReader base, Class<T> type) {
        super(base);
        clz = type;
    }

    @Override
    public T createObject() {
        return (T) ClassUtils.newInstance(clz);
    }

    public static class NOPCustomMapper extends CustomMapper<Object> {

        /**
         * Reader can be link to the JsonReader Base
         *
         * @param base
         */
        public NOPCustomMapper(JSONReader base) {
            super(base, Object.class);
        }
    }
}
