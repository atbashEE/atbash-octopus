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
package be.atbash.ee.openid.connect.sdk.claims;


import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;


/**
 * Tests the AMR class.
 */
public class AMRTest {

    @Test
    public void testConstants() {

        assertThat(AMR.FACE.getValue()).isEqualTo("face");
        assertThat(AMR.FPT.getValue()).isEqualTo("fpt");
        assertThat(AMR.GEO.getValue()).isEqualTo("geo");
        assertThat(AMR.HWK.getValue()).isEqualTo("hwk");
        assertThat(AMR.IRIS.getValue()).isEqualTo("iris");
        assertThat(AMR.KBA.getValue()).isEqualTo("kba");
        assertThat(AMR.MCA.getValue()).isEqualTo("mca");
        assertThat(AMR.MFA.getValue()).isEqualTo("mfa");
        assertThat(AMR.OTP.getValue()).isEqualTo("otp");
        assertThat(AMR.PIN.getValue()).isEqualTo("pin");
        assertThat(AMR.PWD.getValue()).isEqualTo("pwd");
        assertThat(AMR.RBA.getValue()).isEqualTo("rba");
        assertThat(AMR.SC.getValue()).isEqualTo("sc");
        assertThat(AMR.SMS.getValue()).isEqualTo("sms");
        assertThat(AMR.TEL.getValue()).isEqualTo("tel");
        assertThat(AMR.USER.getValue()).isEqualTo("user");
        assertThat(AMR.VBM.getValue()).isEqualTo("vbm");
        assertThat(AMR.WIA.getValue()).isEqualTo("wia");

        // deprecated
        assertThat(AMR.POP.getValue()).isEqualTo("pop");
        assertThat(AMR.EYE.getValue()).isEqualTo("eye");
    }
}
