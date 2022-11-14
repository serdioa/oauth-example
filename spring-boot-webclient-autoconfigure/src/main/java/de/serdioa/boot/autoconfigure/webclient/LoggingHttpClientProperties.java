package de.serdioa.boot.autoconfigure.webclient;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

import lombok.Data;


@Data
public class LoggingHttpClientProperties {

    private static final AtomicLong counter = new AtomicLong();

    private String name = "webclient-" + counter.incrementAndGet();
    private boolean enabled = true;
    private DetailLogProperties request = new DetailLogProperties();
    private DetailLogProperties response = new DetailLogProperties();


    @Data
    public static class DetailLogProperties {

        private boolean enabled = true;
        private DetailHeadersLogProperties headers = new DetailHeadersLogProperties();
        private DetailBodyLogProperties body = new DetailBodyLogProperties();
    }


    @Data
    public static class DetailHeadersLogProperties {

        private boolean enabled = false;

        private Set<Pattern> include = new HashSet<>();
        private Set<Pattern> exclude = new HashSet<>();


        public boolean isLogHeader(String header) {
            if (header == null || !this.enabled) {
                return false;
            }

            // "Exclude" has higher priority over "include".
            // If "exclude" is empty, it matches none (i.e. exclude none).
            if (this.exclude != null && this.isMatchAny(header, this.exclude)) {
                // The header is explicitly excluded by the regular expression.
                return false;
            }

            // If "include" is empty, it matches all (i.e. include all).
            if (this.include == null || this.include.isEmpty()) {
                // There are no "include" patterns, so the header is implicitly included.
                return true;
            } else {
                // There are some "include" paterns, check if the header is explicitly included.
                return this.isMatchAny(header, this.include);
            }
        }


        private boolean isMatchAny(String header, Set<Pattern> regex) {
            for (Pattern pattern : regex) {
                if (pattern.matcher(header).matches()) {
                    return true;
                }
            }

            return false;
        }
    }


    @Data
    public static class DetailBodyLogProperties {

        private boolean enabled = true;
    }
}
