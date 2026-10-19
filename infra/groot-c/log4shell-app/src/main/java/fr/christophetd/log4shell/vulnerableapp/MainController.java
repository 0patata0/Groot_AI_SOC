package fr.christophetd.log4shell.vulnerableapp;

import java.io.IOException;
import java.io.InputStream;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import org.apache.logging.log4j.core.LoggerContext;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class MainController {
    private static final Logger logger = LogManager.getLogger("GrootLog4ShellLab");
    private static final ZoneId KST = ZoneId.of("Asia/Seoul");
    private final LabCsrf csrf = new LabCsrf();

    @GetMapping(value = "/status", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> status(HttpServletRequest request, HttpServletResponse response) {
        noStore(response);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ok", true);
        result.put("csrfToken", csrf.issue(request, response));
        result.put("log4jApiVersion", packageVersion(LogManager.class, "log4j-api"));
        result.put("log4jCoreVersion", packageVersion(LoggerContext.class, "log4j-core"));
        result.put("javaVersion", System.getProperty("java.version"));
        result.put("time", now());
        return result;
    }

    @PostMapping(value = "/log", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> log(HttpServletRequest request, HttpServletResponse response) {
        noStore(response);
        if (!csrf.accepts(request)) {
            return error(response, 403, "csrf_refresh_required");
        }
        String source = request.getParameter("source");
        String headerName = null;
        String raw;
        if ("header".equals(source)) {
            headerName = request.getParameter("headerName");
            if (!"X-Api-Version".equals(headerName) && !"User-Agent".equals(headerName)) {
                return error(response, 400, "unsupported_header_name");
            }
            raw = request.getHeader(headerName);
        } else if ("parameter".equals(source)) {
            raw = request.getParameter("message");
        } else {
            return error(response, 400, "unsupported_source");
        }
        if (raw == null) {
            return error(response, 400, "missing_input");
        }

        String requestId = UUID.randomUUID().toString();
        String time = now();
        ThreadContext.put("requestId", requestId);
        ThreadContext.put("source", "header".equals(source) ? headerName : "message");
        try {
            // Intentional vulnerability for this isolated lab. Do not sanitize,
            // trim, substitute, or interpret input before this logging call.
            logger.info(raw);
        } finally {
            ThreadContext.remove("requestId");
            ThreadContext.remove("source");
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ok", true);
        result.put("source", source);
        if (headerName != null) {
            result.put("headerName", headerName);
        }
        result.put("message", raw);
        result.put("level", "INFO");
        result.put("time", time);
        result.put("requestId", requestId);
        return result;
    }

    private static Map<String, Object> error(HttpServletResponse response, int status, String code) {
        response.setStatus(status);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ok", false);
        result.put("error", code);
        return result;
    }

    private static void noStore(HttpServletResponse response) {
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("X-Content-Type-Options", "nosniff");
    }

    private static String now() {
        return OffsetDateTime.now(KST).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
    }

    private static String packageVersion(Class<?> type, String artifact) {
        String version = type.getPackage().getImplementationVersion();
        if (version != null) {
            return version;
        }
        String path = "/META-INF/maven/org.apache.logging.log4j/" + artifact + "/pom.properties";
        try (InputStream input = type.getResourceAsStream(path)) {
            if (input != null) {
                Properties properties = new Properties();
                properties.load(input);
                return properties.getProperty("version");
            }
        } catch (IOException unavailable) {
            // No declared-version fallback: null means runtime metadata was unavailable.
        }
        return null;
    }
}
