package co.medistock.security.adapters;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.*;
import tools.jackson.databind.json.JsonMapper;
public final class Errors {
    private final JsonMapper mapper = JsonMapper.builder().build();
    public Map<String,Object> body(HttpServletRequest request, String code, String message, Object details) {
        var body = new LinkedHashMap<String,Object>();
        body.put("error", code); body.put("message", message);
        if (details != null) body.put("details", details);
        body.put("traceId", request.getAttribute("traceId"));
        return body;
    }
    public void write(HttpServletRequest request, HttpServletResponse response, int status, String code, String message, Object details) throws IOException {
        response.setStatus(status); response.setContentType("application/json"); response.setCharacterEncoding("UTF-8");
        response.getWriter().write(mapper.writeValueAsString(body(request, code, message, details)));
    }
}
