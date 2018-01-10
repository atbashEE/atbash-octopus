/**
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
package be.atbash.ee.security.octopus.authz.permission

import be.atbash.ee.security.octopus.authz.permission.testclasses.Data
import be.atbash.json.JSONValue
import spock.lang.Specification

/**
 *
 */

class JSONEncoderTest extends Specification {

    def "customEncoder"() {
        when:

        Data data = new Data()
        data.name = "Spock"
        data.permisions = [new WildcardPermission("domain1:action1:*"), new WildcardPermission("domain2:*:*")] as List

        then:
        JSONValue.toJSONString(data) == "{\"permisions\":[\"domain1:action1:*\",\"domain2:*:*\"],\"name\":\"Spock\"}"
    }

    def "customDecoder"() {


        when:

        Data data = (Data) JSONValue.parse("{\"permisions\":[\"domain1:action1:*\",\"domain2:*:*\"],\"name\":\"Spock\"}")

        then:
        data.permisions == [new WildcardPermission("domain1:action1:*"), new WildcardPermission("domain2:*:*")] as List
    }
}