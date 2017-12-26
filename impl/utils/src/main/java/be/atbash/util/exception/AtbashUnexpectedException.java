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
package be.atbash.util.exception;

import be.atbash.util.Reviewed;

/**
 * Developer can use this to rethrow an exception when we know that it should never happen.
 * It allows th capture a checked exception and propagate it as un unchecked.
 */
@Reviewed
public class AtbashUnexpectedException extends AtbashException {

    public AtbashUnexpectedException(String message) {
        super(message);
    }

    public AtbashUnexpectedException(Throwable cause) {
        super(cause);
    }

}
