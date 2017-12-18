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
package be.atbash.json.style;

/*
 *    Copyright 2011 JSON-SMART authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import java.io.IOException;

/**
 * protected class used to stored Internal methods
 *
 * @author Uriel Chemouni &lt;uchemouni@gmail.com&gt;
 */
class JStylerObj {

    final static Escape4Web ESCAPE4Web = new Escape4Web();

    public interface StringProtector {
        void escape(String s, Appendable out);
    }

    private static class Escape4Web implements StringProtector {

        /**
         * Escape special chars form String including /
         *
         * @param s  - Must not be null.
         * @param sb
         */
        public void escape(String s, Appendable sb) {
            try {
                int len = s.length();
                for (int i = 0; i < len; i++) {
                    char ch = s.charAt(i);
                    switch (ch) {
                        case '"':
                            sb.append("\\\"");
                            break;
                        case '\\':
                            sb.append("\\\\");
                            break;
                        case '\b':
                            sb.append("\\b");
                            break;
                        case '\f':
                            sb.append("\\f");
                            break;
                        case '\n':
                            sb.append("\\n");
                            break;
                        case '\r':
                            sb.append("\\r");
                            break;
                        case '\t':
                            sb.append("\\t");
                            break;
                        case '/':
                            sb.append("\\/");
                            break;
                        default:
                            // Reference:
                            // http://www.unicode.org/versions/Unicode5.1.0/
                            if ((ch >= '\u0000' && ch <= '\u001F') || (ch >= '\u007F' && ch <= '\u009F')
                                    || (ch >= '\u2000' && ch <= '\u20FF')) {
                                sb.append("\\u");
                                String hex = "0123456789ABCDEF";
                                sb.append(hex.charAt(ch >> 12 & 0x0F));
                                sb.append(hex.charAt(ch >> 8 & 0x0F));
                                sb.append(hex.charAt(ch >> 4 & 0x0F));
                                sb.append(hex.charAt(ch >> 0 & 0x0F));
                            } else {
                                sb.append(ch);
                            }
                    }
                }
            } catch (IOException e) {
                throw new RuntimeException("Impossible Error");
            }
        }
    }
}
