package co.medistock.security.core;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
class AuthenticateTest {
    private final Account active=new Account(UUID.randomUUID(),"admin","Demo","stored",true,List.of("ADMIN"));
    private Authenticate service(Account account,List<String> hashes) {
        return new Authenticate(new Accounts() {
            public Optional<Account> byUsername(String name) { return account!=null && account.username().equals(name)?Optional.of(account):Optional.empty(); }
            public Optional<Account> byId(UUID id) { return account!=null && account.id().equals(id)?Optional.of(account):Optional.empty(); }
        },(raw,hash)->{hashes.add(hash);return raw.equals("correct");},"dummy");
    }
    @Test void normalizesUsername() { assertEquals(active,service(active,new ArrayList<>()).login(" ADMIN ","correct")); }
    @Test void rejectsWrongPassword() { assertThrows(InvalidCredentials.class,()->service(active,new ArrayList<>()).login("admin","incorrect")); }
    @Test void checksDummyHashForMissingAccount() {
        var hashes=new ArrayList<String>();assertThrows(InvalidCredentials.class,()->service(null,hashes).login("missing","correct"));assertEquals(List.of("dummy"),hashes);
    }
    @Test void rejectsInactiveAccounts() {
        var inactive=new Account(active.id(),"admin","Demo","stored",false,List.of("ADMIN"));
        assertThrows(InvalidCredentials.class,()->service(inactive,new ArrayList<>()).login("admin","correct"));
        assertThrows(InvalidCredentials.class,()->service(inactive,new ArrayList<>()).current(inactive.id()));
    }
    @Test void rejectsUnknownRole() { assertThrows(IllegalArgumentException.class,()->new Account(UUID.randomUUID(),"demo","Demo","hash",true,List.of("UNKNOWN"))); }
}
