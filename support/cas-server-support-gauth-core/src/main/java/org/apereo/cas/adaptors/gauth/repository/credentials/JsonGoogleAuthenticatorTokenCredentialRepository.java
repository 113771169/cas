package org.apereo.cas.adaptors.gauth.repository.credentials;

import org.apereo.cas.CipherExecutor;
import org.apereo.cas.authentication.OneTimeTokenAccount;
import org.apereo.cas.util.serialization.AbstractJacksonBackedStringSerializer;
import org.apereo.cas.util.serialization.StringSerializer;

import com.warrenstrange.googleauth.IGoogleAuthenticator;
import lombok.Getter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.commons.lang3.StringUtils;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.TreeSet;

/**
 * This is {@link JsonGoogleAuthenticatorTokenCredentialRepository}.
 *
 * @author Misagh Moayyed
 * @since 5.1.0
 */
@Getter
@Slf4j
public class JsonGoogleAuthenticatorTokenCredentialRepository extends BaseGoogleAuthenticatorTokenCredentialRepository {
    private final Resource location;
    private final StringSerializer<TreeSet<OneTimeTokenAccount>> serializer = new OneTimeAccountSerializer();

    public JsonGoogleAuthenticatorTokenCredentialRepository(final Resource location, final IGoogleAuthenticator googleAuthenticator,
                                                            final CipherExecutor<String, String> tokenCredentialCipher) {
        super(tokenCredentialCipher, googleAuthenticator);
        this.location = location;
    }

    @Override
    public OneTimeTokenAccount get(final String username) {
        try {
            if (!this.location.getFile().exists()) {
                LOGGER.warn("JSON account repository file [{}] is not found.", this.location.getFile());
                return null;
            }

            if (this.location.getFile().length() <= 0) {
                LOGGER.warn("JSON account repository file [{}] is empty.", this.location.getFile());
                return null;
            }
            val c = this.serializer.from(this.location.getFile());
            val account = c.stream()
                .filter(a -> StringUtils.isNotBlank(a.getUsername()) && a.getUsername().equals(username))
                .findAny()
                .orElse(null);
            if (account != null) {
                return decode(account);
            }
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }

    @Override
    public void save(final String userName, final String secretKey,
                     final int validationCode, final List<Integer> scratchCodes) {
        try {
            LOGGER.debug("Storing google authenticator account for [{}]", userName);
            val account = new OneTimeTokenAccount(userName, secretKey, validationCode, scratchCodes);
            update(account);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public OneTimeTokenAccount update(final OneTimeTokenAccount account) {
        try {
            val accounts = readAccountsFromJsonRepository();

            LOGGER.debug("Found [{}] account(s) and added google authenticator account for [{}]", accounts.size(), account.getUsername());
            val encoded = encode(account);
            accounts.add(encoded);

            writeAccountsToJsonRepository(accounts);
            return encoded;
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }

    @Override
    public void deleteAll() {
        writeAccountsToJsonRepository(new TreeSet<>());
    }

    @Override
    public void delete(final String username) {
        try {
            val accounts = readAccountsFromJsonRepository();
            accounts.removeIf(t -> t.getUsername().equalsIgnoreCase(username));
            writeAccountsToJsonRepository(accounts);
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
    }

    @Override
    public long count() {
        try {
            val accounts = readAccountsFromJsonRepository();
            return accounts.size();
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return 0;
    }

    @Override
    public Collection<? extends OneTimeTokenAccount> load() {
        try {
            return readAccountsFromJsonRepository();
        } catch (final Exception e) {
            LOGGER.error(e.getMessage(), e);
        }
        return new ArrayList<>();
    }

    @SneakyThrows
    private void writeAccountsToJsonRepository(final TreeSet<OneTimeTokenAccount> accounts) {
        LOGGER.debug("Saving google authenticator accounts back to the JSON file at [{}]", this.location.getFile());
        this.serializer.to(this.location.getFile(), accounts);
    }

    private TreeSet<OneTimeTokenAccount> readAccountsFromJsonRepository() throws IOException {
        LOGGER.debug("Ensuring JSON repository file exists at [{}]", this.location.getFile());
        val result = this.location.getFile().createNewFile();
        if (result) {
            LOGGER.debug("Created JSON repository file at [{}]", this.location.getFile());
        }
        val accounts = new TreeSet<OneTimeTokenAccount>();
        if (this.location.getFile().length() > 0) {
            LOGGER.debug("Reading JSON repository file at [{}]", this.location.getFile());
            accounts.addAll(this.serializer.from(this.location.getFile()));
        }
        return accounts;
    }

    private static class OneTimeAccountSerializer extends AbstractJacksonBackedStringSerializer<TreeSet<OneTimeTokenAccount>> {
        private static final long serialVersionUID = 1466569521275630254L;

        @Override
        protected Class getTypeToSerialize() {
            return TreeSet.class;
        }
    }
}
