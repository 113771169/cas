package org.apereo.cas.adaptors.gauth.credential;

import org.apereo.cas.CipherExecutor;
import org.apereo.cas.adaptors.gauth.repository.credentials.RestGoogleAuthenticatorTokenCredentialRepository;
import org.apereo.cas.category.RestfulApiCategory;
import org.apereo.cas.config.CasCoreUtilConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.otp.repository.credentials.OneTimeTokenCredentialRepository;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.val;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.aop.AopAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.autoconfigure.RefreshAutoConfiguration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.rules.SpringClassRule;
import org.springframework.test.context.junit4.rules.SpringMethodRule;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

/**
 * This is {@link RestGoogleAuthenticatorTokenCredentialRepositoryTests}.
 *
 * @author Misagh Moayyed
 * @since 5.3.0
 */
@SpringBootTest(classes = {
    AopAutoConfiguration.class,
    RefreshAutoConfiguration.class,
    CasCoreUtilConfiguration.class
    }, properties = {
    "cas.authn.mfa.gauth.rest.endpointUrl=http://example.com"
})
@Category(RestfulApiCategory.class)
@EnableConfigurationProperties(CasConfigurationProperties.class)
public class RestGoogleAuthenticatorTokenCredentialRepositoryTests extends AbstractGoogleAuthenticatorTokenCredentialRepositoryTests {
    @ClassRule
    public static final SpringClassRule SPRING_CLASS_RULE = new SpringClassRule();

    private static final ObjectMapper MAPPER = new ObjectMapper().findAndRegisterModules();

    @Rule
    public final SpringMethodRule springMethodRule = new SpringMethodRule();

    private final Map<String, OneTimeTokenCredentialRepository> repositoryMap = new HashMap<>();

    @Autowired
    private CasConfigurationProperties casProperties;

    @Override
    public OneTimeTokenCredentialRepository getRepository(final String testName) {
        return repositoryMap.computeIfAbsent(testName, name -> {
            return new RestGoogleAuthenticatorTokenCredentialRepository(getGoogle(), new RestTemplate(),
                casProperties.getAuthn().getMfa().getGauth(),
                CipherExecutor.noOpOfStringToString());
        });
    }

    @Test
    @Override
    public void verifyGet() {
        val repository = (RestGoogleAuthenticatorTokenCredentialRepository) getRepository("verifyGet");
        assertNotNull("Repository is null", repository);
        val mockServer = MockRestServiceServer.createServer(repository.getRestTemplate());
        try {
            mockServer.expect(requestTo("http://example.com"))
                .andExpect(method(HttpMethod.GET)).andRespond(withNoContent());
            mockServer.expect(requestTo("http://example.com"))
                .andExpect(method(HttpMethod.POST)).andRespond(withSuccess("", MediaType.APPLICATION_JSON));
            mockServer.expect(requestTo("http://example.com"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(MAPPER.writeValueAsString(getAccount("verifyGet", "casuser")), MediaType.APPLICATION_JSON));
        } catch (final JsonProcessingException e) {
            throw new AssertionError(e);
        }
        super.verifyGet();
        mockServer.verify();
    }
}
