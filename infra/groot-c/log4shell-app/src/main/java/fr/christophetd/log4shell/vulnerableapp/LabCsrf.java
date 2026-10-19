package fr.christophetd.log4shell.vulnerableapp;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/** CSRF provenance only; this is not a login or authorization mechanism. */
final class LabCsrf {
    private static final String HTTP_COOKIE = "groot_log4shell_java_http";
    private static final String HTTPS_COOKIE = "__Secure-groot_log4shell_java_https";
    private static final long LIFETIME_SECONDS = 30 * 60;
    private final SecureRandom random = new SecureRandom();
    private final byte[] key = new byte[32];

    LabCsrf() {
        random.nextBytes(key);
    }

    String issue(HttpServletRequest request, HttpServletResponse response) {
        String name = cookieName(request);
        byte[] nonce = new byte[32];
        random.nextBytes(nonce);
        byte[] body = ByteBuffer.allocate(40).putLong(Instant.now().getEpochSecond()).put(nonce).array();
        byte[] signed = ByteBuffer.allocate(72).put(body).put(sign(name, body)).array();
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(signed);
        String cookie = name + "=" + token + "; Path=" + request.getContextPath()
                + "/; Max-Age=" + LIFETIME_SECONDS + "; HttpOnly; SameSite=Strict";
        if (isSecure(request)) {
            cookie += "; Secure";
        }
        response.addHeader("Set-Cookie", cookie);
        return token;
    }

    boolean accepts(HttpServletRequest request) {
        String name = cookieName(request);
        String header = request.getHeader("X-Lab-CSRF-Token");
        if (header == null || header.length() != 96) {
            return false;
        }
        String cookieValue = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (name.equals(cookie.getName())) {
                    if (cookieValue != null) {
                        return false;
                    }
                    cookieValue = cookie.getValue();
                }
            }
        }
        if (cookieValue == null || !MessageDigest.isEqual(header.getBytes(StandardCharsets.US_ASCII),
                cookieValue.getBytes(StandardCharsets.US_ASCII))) {
            return false;
        }
        try {
            byte[] signed = Base64.getUrlDecoder().decode(header);
            if (signed.length != 72) {
                return false;
            }
            byte[] body = Arrays.copyOf(signed, 40);
            long issued = ByteBuffer.wrap(body).getLong();
            long now = Instant.now().getEpochSecond();
            return issued <= now && issued >= now - LIFETIME_SECONDS
                    && MessageDigest.isEqual(Arrays.copyOfRange(signed, 40, 72), sign(name, body));
        } catch (IllegalArgumentException invalidToken) {
            return false;
        }
    }

    private byte[] sign(String name, byte[] body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            mac.update(name.getBytes(StandardCharsets.US_ASCII));
            return mac.doFinal(body);
        } catch (GeneralSecurityException unavailable) {
            throw new IllegalStateException("CSRF signing unavailable", unavailable);
        }
    }

    private static String cookieName(HttpServletRequest request) {
        return isSecure(request) ? HTTPS_COOKIE : HTTP_COOKIE;
    }

    private static boolean isSecure(HttpServletRequest request) {
        // The existing A proxy overwrites this hint. It only selects cookie flags;
        // it never authenticates a request or controls where its input is logged.
        return request.isSecure() || "1".equals(request.getHeader("X-Groot-Lab-TLS"));
    }
}
