package co.medistock.security.core;
public interface PasswordVerifier {
    boolean matches(String raw, String hash);
}
