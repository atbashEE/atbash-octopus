/*
 * Copyright 2014-2019 Rudy De Busscher (https://www.atbash.be)
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
package be.atbash.ee.oauth2.sdk.auth.verifier;


/**
 * Generic context for passing objects.
 */
// FIXME Used or just passed around?
public class Context<T> {


    /**
     * The context content.
     */
    private T o;


    /**
     * Sets the context content.
     *
     * @param o The context content.
     */
    public void set(final T o) {

        this.o = o;
    }


    /**
     * Gets the context content.
     *
     * @return The context content.
     */
    public T get() {

        return o;
    }
}
