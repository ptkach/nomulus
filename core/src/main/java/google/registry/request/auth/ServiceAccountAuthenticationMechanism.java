package google.registry.request.auth;

import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static google.registry.request.auth.AuthLevel.APP;

import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.auth.oauth2.TokenVerifier;
import com.google.common.flogger.FluentLogger;
import google.registry.config.RegistryConfig.Config;
import google.registry.config.RegistryEnvironment;
import google.registry.model.console.User;
import java.util.Optional;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;
import javax.inject.Inject;

/**
 * A way to authenticate HTTP requests signed by Service Account
 *
 * <p>Currently used by cloud scheduler service account
 */
public class ServiceAccountAuthenticationMechanism implements AuthenticationMechanism {
  private final String projectId;
  private final TokenVerifier tokenVerifier;
  private final String cloudSchedulerEmailPrefix;
  private static final String BEARER_PREFIX = "Bearer ";
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private static Optional<User> userForTesting = Optional.empty();

  @Inject
  public ServiceAccountAuthenticationMechanism(
      @Named("serviceAccount") TokenVerifier tokenVerifier,
      @Config("projectId") String projectId,
      @Config("cloudSchedulerServiceAccountEmailPrefix") String cloudSchedulerEmailPrefix

  ) {
    this.tokenVerifier = tokenVerifier;
    this.projectId = projectId;
    this.cloudSchedulerEmailPrefix = cloudSchedulerEmailPrefix;
  }

  @Override
  public AuthResult authenticate(HttpServletRequest request) {
    if (RegistryEnvironment.get().equals(RegistryEnvironment.UNITTEST)
        && userForTesting.isPresent()) {
      return AuthResult.create(APP);
    }
    String rawIdToken = request.getHeader(AUTHORIZATION);
    if (rawIdToken == null) {
      return AuthResult.NOT_AUTHENTICATED;
    }
    String rawAccessToken = rawIdToken.substring(BEARER_PREFIX.length());
    JsonWebSignature token;
    try {
      token = tokenVerifier.verify(rawAccessToken);
    } catch (TokenVerifier.VerificationException e) {
      return AuthResult.NOT_AUTHENTICATED;
    }
    String emailAddress = (String) token.getPayload().get("email");
    if (emailAddress.startsWith(cloudSchedulerEmailPrefix)) {
      return AuthResult.create(APP);
    } else {
      return AuthResult.NOT_AUTHENTICATED;
    }
  }
}
