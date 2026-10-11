package co.medistock.security.core;
import java.util.Locale;
import java.util.UUID;
public final class Authenticate {
    private final Accounts accounts;
    private final PasswordVerifier verifier;
    private final String dummyHash;
    public Authenticate(Accounts accounts, PasswordVerifier verifier, String dummyHash) {
        this.accounts = accounts; this.verifier = verifier; this.dummyHash = dummyHash;
    }
    public Account login(String username, String password) {
        var found = accounts.byUsername(username.strip().toLowerCase(Locale.ROOT));
        boolean matches = verifier.matches(password, found.map(Account::passwordHash).orElse(dummyHash));
        return found.filter(account -> account.active() && matches).orElseThrow(InvalidCredentials::new);
    }
    public Account current(UUID id) {
        return accounts.byId(id).filter(Account::active).orElseThrow(InvalidCredentials::new);
    }
}
