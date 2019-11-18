package com.cx.restclient.sast.dto;

import java.util.Locale;

public enum SupportedLanguage {

    ENGLISH_US(Locale.US, "EEEE, MMMM dd, yyyy hh:mm:ss a"),
    ENGLISH_GB(Locale.ENGLISH, "dd MMMM yyyy hh:mm"),
    FRENCH_FR(Locale.FRENCH, "EEEE dd MMMM yyyy hh:mm"),
    PORTUGUESE_PT(new Locale("pt"), "dd 'de' MMMM 'de' yyyy hh:mm"),
    SPANISH(new Locale("es"), "EEEE, dd 'de' MMMM 'de' YYYY hh:mm"),
    RUSSIAN(new Locale("ru"), "dd MMMM yyyy 'г.' hh:mm");

    //TODO: Add fitting format
//    JAPANESE(new Locale("ja-JP"), "ss"),
//    KOREAN(new Locale("ko-KR"), "ss"),
//    PORTUGUESE_BR(new Locale("pt-BR"), "ss"),
//    CHINESE_CN(new Locale("zn-CN"), "ss"),
//    CHINESE_TW(new Locale("zn-TW"), "ss");

    private final Locale locale;
    private final String format;

    SupportedLanguage(Locale locale, String format) {
        this.format = format;
        this.locale = locale;
    }

    public Locale getLocale() {
        return locale;
    }

    public String getFormat() {
        return format;
    }
}
