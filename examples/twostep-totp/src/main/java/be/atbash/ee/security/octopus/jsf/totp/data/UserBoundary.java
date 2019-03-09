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
package be.atbash.ee.security.octopus.jsf.totp.data;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Named;
import java.util.ArrayList;
import java.util.List;

@ApplicationScoped
@Named
public class UserBoundary {

    private List<UserData> users;

    @PostConstruct
    public void init() {
        users = new ArrayList<>();
        users.add(new UserData("rudy", "Rudy De Busscher", "EB4Q5HMDC5LYDO56OMDAN5U6DWL2LKGLMMDNL4BUW4LEJNB3AHYM5HBGKAWNV6MHB65K5DIIS3WENGMHQBROASDHU244NKH2LNLOT4FR4WMSIM5BN647I3V6QHDD4355FKXJQFCCRUHPMQVYDPUYC4KBT4NMUYD7X4N6TU4JZE4CTCTW4BHC7SVV5SCKFNAWGXVJIGRWR4TEE"));
        users.add(new UserData("test", "Test User", "KFQKTQWB57QJH3D4GYG2GYBBHCBIHHLWA2O7X4ZEAN4ZWTXFKZUM7GDMTRDCSCEJ5GQI4PFSMWNOZVOTGSBI3JNCMMP6FINFO7WAKYKVKGE4MUONWXRCIVF5BWYBT6DV64TQCMIMMWAEFZFKRJVI2MHMSFJRUTVTUI7XBSU2FGRDBJKKT3ECGRHJU5CQCDYANBNXNR55XMNKG"));
    }

    public List<UserData> getUsers() {
        return users;
    }

    public UserData getData(final String userName) {
        UserData result = null;
        for (UserData user : users) {
            if (userName.equals(user.getUserName())) {
                result = user;
            }
        }
        return result;
    }
}
