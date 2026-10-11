package co.medistock.security.adapters;
import co.medistock.security.core.InvalidCredentials;
import jakarta.servlet.http.HttpServletRequest;
import java.util.*;
import org.springframework.dao.DataAccessException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.resource.NoResourceFoundException;
@RestControllerAdvice
public class ApiErrors {
    private final Errors errors;
    public ApiErrors(Errors errors) { this.errors=errors; }
    private ResponseEntity<Map<String,Object>> error(HttpServletRequest r,int status,String code,String message,Object details) {
        return ResponseEntity.status(status).body(errors.body(r,code,message,details));
    }
    @ExceptionHandler(InvalidCredentials.class)
    public ResponseEntity<?> credentials(HttpServletRequest r) { return error(r,401,"UNAUTHORIZED","Credenciales invalidas.",null); }
    @ExceptionHandler(AuthenticationApi.InvalidPasswordSize.class)
    public ResponseEntity<?> passwordSize(HttpServletRequest r) { return error(r,400,"VALIDATION_ERROR","Password demasiado largo.",List.of(Map.of("field","password","message","Maximo 72 bytes UTF-8."))); }
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<?> validation(HttpServletRequest r,MethodArgumentNotValidException e) {
        return error(r,400,"VALIDATION_ERROR","Datos invalidos.",e.getBindingResult().getFieldErrors().stream().map(f -> Map.of("field",f.getField(),"message","Valor invalido.")).toList());
    }
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<?> json(HttpServletRequest r) { return error(r,400,"VALIDATION_ERROR","JSON invalido.",List.of(Map.of("field","body","message","Formato o campo invalido."))); }
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<?> missing(HttpServletRequest r) { return error(r,404,"NOT_FOUND","Ruta inexistente.",null); }
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<?> unavailable(HttpServletRequest r) { return error(r,503,"SERVICE_UNAVAILABLE","Servicio no disponible.",null); }
    @ExceptionHandler(org.springframework.security.access.AccessDeniedException.class)
    public ResponseEntity<?> forbidden(HttpServletRequest r) { return error(r,403,"FORBIDDEN","Permisos insuficientes.",null); }
    @ExceptionHandler(org.springframework.web.HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<?> method(HttpServletRequest r) { return error(r,405,"METHOD_NOT_ALLOWED","Metodo no permitido.",null); }
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> internal(HttpServletRequest r) { return error(r,500,"INTERNAL_ERROR","Error interno.",null); }
}
