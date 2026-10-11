package co.medistock.security.core;
public final class InvalidCredentials extends RuntimeException {
    public InvalidCredentials() { super("Invalid credentials."); }
}
