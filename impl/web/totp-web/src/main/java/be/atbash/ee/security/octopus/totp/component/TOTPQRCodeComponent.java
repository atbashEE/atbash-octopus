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
package be.atbash.ee.security.octopus.totp.component;

import javax.faces.application.ResourceDependency;
import javax.faces.component.FacesComponent;
import javax.faces.component.UIComponentBase;

/**
 *
 */
@FacesComponent("octopus.totpQR")
@ResourceDependency(library = "totp", name = "QRCode.js")
public class TOTPQRCodeComponent extends UIComponentBase {

    //CHECKSTYLE.OFF: WhitespaceAround - { should be followed by space but IntelliJ formatter can't be configured for this type of constructs
    enum PropertyKeys {
        issuer, account, secret, styleClass
    }
    //CHECKSTYLE.ON: WhitespaceAround

    // JSF Configuration
    public TOTPQRCodeComponent() {
        setRendererType("octopus.TotpQRRenderer");

    }

    @Override
    public String getFamily() {
        return "octopus";
    }

    public String getIssuer() {
        return (String) getStateHelper().eval(PropertyKeys.issuer);
    }

    public void setIssuer(String issuer) {
        getStateHelper().put(PropertyKeys.issuer, issuer);
    }

    public String getAccount() {
        return (String) getStateHelper().eval(PropertyKeys.account);

    }

    public void setAccount(String account) {
        getStateHelper().put(PropertyKeys.account, account);
    }

    public String getSecret() {
        return (String) getStateHelper().eval(PropertyKeys.secret);

    }

    public void setSecret(String secret) {
        getStateHelper().put(PropertyKeys.secret, secret);
    }

    public String getStyleClass() {
        return (String) getStateHelper().eval(PropertyKeys.styleClass);

    }

    public void setStyleClass(String styleClass) {
        getStateHelper().put(PropertyKeys.styleClass, styleClass);
    }
}
