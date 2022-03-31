/*
 * Copyright 2014-2020 Rudy De Busscher (https://www.atbash.be)
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

import org.primefaces.renderkit.CoreRenderer;

import jakarta.faces.component.UIComponent;
import jakarta.faces.context.FacesContext;
import jakarta.faces.context.ResponseWriter;
import java.io.IOException;

/**
 *
 */
public class TOTPQRCodeRenderer extends CoreRenderer {

    @Override
    public void encodeEnd(FacesContext context, UIComponent component) throws IOException {
        super.encodeEnd(context, component);

        TOTPQRCodeComponent qrCode = (TOTPQRCodeComponent) component;

        String clientId = renderHtml(context, qrCode);
        String uri = createURI(qrCode);
        renderScript(context, clientId, uri);

    }

    private String createURI(TOTPQRCodeComponent qrCode) {
        return "otpauth://totp/" + qrCode.getIssuer() + ':' + qrCode.getAccount() +
                "?secret=" + qrCode.getSecret();
    }

    private void renderScript(FacesContext context, String clientId, String uri) throws IOException {
        ResponseWriter responseWriter = context.getResponseWriter();
        responseWriter.write("<script type=\"text/javascript\">new QRCode(document.getElementById(\"");
        responseWriter.write(clientId);
        responseWriter.write("\"), \"");
        responseWriter.write(uri);
        responseWriter.write("\");</script>");
    }

    private String renderHtml(FacesContext context, TOTPQRCodeComponent qrCode) throws IOException {
        String clientId = qrCode.getClientId(context);

        ResponseWriter responseWriter = context.getResponseWriter();

        responseWriter.startElement("div", qrCode);
        responseWriter.writeAttribute("id", clientId, null);
        responseWriter.writeAttribute("class", qrCode.getStyleClass(), null);
        responseWriter.endElement("div");

        return clientId;

    }
}
