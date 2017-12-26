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
package be.atbash.json.parser;

import be.atbash.json.writer.CustomMapper;

import java.lang.annotation.*;

/**
 * Atbash added file
 */
@Documented
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface MappedBy {

    Class<? extends JSONEncoder> encoder() default JSONEncoder.NOPJSONEncoder.class;

    Class<? extends CustomMapper> mapper() default CustomMapper.NOPCustomMapper.class;
}
