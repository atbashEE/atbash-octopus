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
package be.atbash.ee.langtag;

import java.util.LinkedList;
import java.util.List;

public class LangTag {
    private String primaryLanguage;
    private String[] languageSubtags;
    private String script;
    private String region;
    private String[] variants;
    private String[] extensions;
    private String privateUse;

    private static void ensureMaxLength(String subtag) throws LangTagException {
        if (subtag.length() > 8 && subtag.charAt(1) != '-' && subtag.length() > 10) {
            throw new LangTagException("Invalid subtag syntax: Max character length exceeded");
        }
    }

    public LangTag(String primaryLanguage) throws LangTagException {
        this(primaryLanguage, (String[]) null);
    }

    public LangTag(String primaryLanguage, String... languageSubtags) throws LangTagException {
        this.script = null;
        this.region = null;
        this.variants = null;
        this.extensions = null;
        this.privateUse = null;
        if (primaryLanguage != null || languageSubtags != null && languageSubtags.length != 0) {
            this.setPrimaryLanguage(primaryLanguage);
            this.setExtendedLanguageSubtags(languageSubtags);
        } else {
            throw new LangTagException("Either the primary language or the extended language subtags, or both must be defined");
        }
    }

    public String getLanguage() {
        StringBuilder sb = new StringBuilder();
        if (this.primaryLanguage != null) {
            sb.append(this.primaryLanguage);
        }

        if (this.languageSubtags != null && this.languageSubtags.length > 0) {
            // FIXME improve code
            String[] var2 = this.languageSubtags;
            int var3 = var2.length;

            for (int var4 = 0; var4 < var3; ++var4) {
                String tag = var2[var4];
                if (sb.length() > 0) {
                    sb.append('-');
                }

                sb.append(tag);
            }
        }

        return sb.toString();
    }

    public String getPrimaryLanguage() {
        return this.primaryLanguage;
    }

    private static boolean isPrimaryLanguage(String s) {
        return s.matches("[a-zA-Z]{2,3}");
    }

    private void setPrimaryLanguage(String primaryLanguage) throws LangTagException {
        if (primaryLanguage == null) {
            this.primaryLanguage = null;
        } else {
            ensureMaxLength(primaryLanguage);
            if (!isPrimaryLanguage(primaryLanguage)) {
                throw new LangTagException("Invalid primary language subtag: Must be a two or three-letter ISO 639 code");
            } else {
                this.primaryLanguage = primaryLanguage.toLowerCase();
            }
        }
    }

    public String[] getExtendedLanguageSubtags() {
        return this.languageSubtags;
    }

    private static boolean isExtendedLanguageSubtag(String s) {
        return s.matches("[a-zA-Z]{3}");
    }

    private void setExtendedLanguageSubtags(String... languageSubtags) throws LangTagException {
        if (languageSubtags != null && languageSubtags.length != 0) {
            this.languageSubtags = new String[languageSubtags.length];

            for (int i = 0; i < languageSubtags.length; ++i) {
                ensureMaxLength(languageSubtags[i]);
                if (!isExtendedLanguageSubtag(languageSubtags[i])) {
                    throw new LangTagException("Invalid extended language subtag: Must be a three-letter ISO 639-3 code");
                }

                this.languageSubtags[i] = languageSubtags[i].toLowerCase();
            }

        } else {
            this.languageSubtags = null;
        }
    }

    public String getScript() {
        return this.script;
    }

    private static boolean isScript(String s) {
        return s.matches("[a-zA-Z]{4}");
    }

    public void setScript(String script) throws LangTagException {
        if (script == null) {
            this.script = null;
        } else {
            ensureMaxLength(script);
            if (!isScript(script)) {
                throw new LangTagException("Invalid script subtag: Must be a four-letter ISO 15924 code");
            } else {
                this.script = script.substring(0, 1).toUpperCase() + script.substring(1).toLowerCase();
            }
        }
    }

    public String getRegion() {
        return this.region;
    }

    private static boolean isRegion(String s) {
        return s.matches("[a-zA-Z]{2}|\\d{3}");
    }

    public void setRegion(String region) throws LangTagException {
        if (region == null) {
            this.region = null;
        } else {
            ensureMaxLength(region);
            if (!isRegion(region)) {
                throw new LangTagException("Invalid region subtag: Must be a two-letter ISO 3166-1 code or a three-digit UN M.49 code");
            } else {
                this.region = region.toUpperCase();
            }
        }
    }

    public String[] getVariants() {
        return this.variants;
    }

    private static boolean isVariant(String s) {
        return s.matches("[a-zA-Z][a-zA-Z0-9]{4,}|[0-9][a-zA-Z0-9]{3,}");
    }

    public void setVariants(String... variants) throws LangTagException {
        if (variants != null && variants.length != 0) {
            this.variants = new String[variants.length];

            for (int i = 0; i < variants.length; ++i) {
                ensureMaxLength(variants[i]);
                if (!isVariant(variants[i])) {
                    throw new LangTagException("Invalid variant subtag");
                }

                this.variants[i] = variants[i].toLowerCase();
            }

        } else {
            this.variants = null;
        }
    }

    public String[] getExtensions() {
        return this.extensions;
    }

    private static boolean isExtensionSingleton(String s) {
        return s.matches("[0-9a-wA-Wy-zY-Z]");
    }

    private static boolean isExtension(String s) {
        return s.matches("[0-9a-wA-Wy-zY-Z]-[0-9a-zA-Z]+");
    }

    public void setExtensions(String... extensions) throws LangTagException {
        if (extensions != null && extensions.length != 0) {
            this.extensions = new String[extensions.length];

            for (int i = 0; i < extensions.length; ++i) {
                ensureMaxLength(extensions[i]);
                if (!isExtension(extensions[i])) {
                    throw new LangTagException("Invalid extension subtag");
                }

                this.extensions[i] = extensions[i].toLowerCase();
            }

        } else {
            this.extensions = null;
        }
    }

    public String getPrivateUse() {
        return this.privateUse;
    }

    private static boolean isPrivateUse(String s) {
        return s.matches("x-[0-9a-zA-Z]+");
    }

    public void setPrivateUse(String privateUse) throws LangTagException {
        if (privateUse == null) {
            this.privateUse = null;
        } else {
            ensureMaxLength(privateUse);
            if (!isPrivateUse(privateUse)) {
                throw new LangTagException("Invalid private use subtag");
            } else {
                this.privateUse = privateUse.toLowerCase();
            }
        }
    }

    public String toString() {
        StringBuilder sb = new StringBuilder(this.getLanguage());
        if (this.script != null) {
            sb.append('-');
            sb.append(this.script);
        }

        if (this.region != null) {
            sb.append('-');
            sb.append(this.region);
        }

        String[] var2;
        int var3;
        int var4;
        String e;
        if (this.variants != null) {
            var2 = this.variants;
            var3 = var2.length;

            for (var4 = 0; var4 < var3; ++var4) {
                e = var2[var4];
                sb.append('-');
                sb.append(e);
            }
        }

        if (this.extensions != null) {
            var2 = this.extensions;
            var3 = var2.length;

            for (var4 = 0; var4 < var3; ++var4) {
                e = var2[var4];
                sb.append('-');
                sb.append(e);
            }
        }

        if (this.privateUse != null) {
            sb.append('-');
            sb.append(this.privateUse);
        }

        return sb.toString();
    }

    public int hashCode() {
        return this.toString().hashCode();
    }

    public boolean equals(Object object) {
        return object instanceof LangTag && this.toString().equals(object.toString());
    }

    public static LangTag parse(String s) throws LangTagException {
        if (s != null && !s.trim().isEmpty()) {
            String[] subtags = s.split("-");
            int pos = 0;
            String primaryLang = null;
            List<String> extLangSubtags = new LinkedList<>();
            if (isPrimaryLanguage(subtags[0])) {
                primaryLang = subtags[pos++];
            }

            while (pos < subtags.length && isExtendedLanguageSubtag(subtags[pos])) {
                extLangSubtags.add(subtags[pos++]);
            }

            LangTag langTag = new LangTag(primaryLang, extLangSubtags.toArray(new String[0]));
            if (pos < subtags.length && isScript(subtags[pos])) {
                langTag.setScript(subtags[pos++]);
            }

            if (pos < subtags.length && isRegion(subtags[pos])) {
                langTag.setRegion(subtags[pos++]);
            }

            LinkedList<String> variantSubtags = new LinkedList<>();

            while (pos < subtags.length && isVariant(subtags[pos])) {
                variantSubtags.add(subtags[pos++]);
            }

            if (!variantSubtags.isEmpty()) {
                langTag.setVariants(variantSubtags.toArray(new String[0]));
            }

            LinkedList<String> extSubtags = new LinkedList<>();

            while (pos < subtags.length && isExtensionSingleton(subtags[pos])) {
                String singleton = subtags[pos++];
                if (pos == subtags.length) {
                    throw new LangTagException("Invalid extension subtag");
                }

                extSubtags.add(singleton + "-" + subtags[pos++]);
            }

            if (!extSubtags.isEmpty()) {
                langTag.setExtensions(extSubtags.toArray(new String[0]));
            }

            if (pos < subtags.length && subtags[pos].equals("x")) {
                ++pos;
                if (pos == subtags.length) {
                    throw new LangTagException("Invalid private use subtag");
                }

                langTag.setPrivateUse("x-" + subtags[pos++]);
            }

            if (pos < subtags.length) {
                throw new LangTagException("Invalid language tag: Unexpected subtag");
            } else {
                return langTag;
            }
        } else {
            return null;
        }
    }
}
