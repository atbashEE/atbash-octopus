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
package be.atbash.ee.security.octopus.subject;

/**
 * This is the interface to separate Java SE and Web code. Otherwise the Java SE version should be creating
 * an Subject when none is available on the Thread instance. This requires then a lot of Java SE specific code within core
 * which should be usable by both environments.
 */

public interface SubjectResolver {

    <T extends Subject> T getSubject();
}
