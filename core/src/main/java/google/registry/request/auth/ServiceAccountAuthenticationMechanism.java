// Copyright 2023 The Nomulus Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package google.registry.request.auth;

import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static google.registry.request.auth.AuthLevel.APP;

import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.auth.oauth2.TokenVerifier;
import google.registry.config.RegistryConfig.Config;
import google.registry.config.RegistryEnvironment;
import google.registry.model.console.User;
import java.util.Optional;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

/**
 * A way to authenticate HTTP requests signed by Service Account
 *
 * <p>Currently used by cloud scheduler service account
 */
public class ServiceAccountAuthenticationMechanism implements AuthenticationMechanism {
  private final TokenVerifier tokenVerifier;
  private final String cloudSchedulerEmailPrefix;
  private static final String BEARER_PREFIX = "Bearer ";
  private static Optional<User> userForTesting = Optional.empty();

  @Inject
  public ServiceAccountAuthenticationMechanism(
      @Named("serviceAccount") TokenVerifier tokenVerifier,
      @Config("cloudSchedulerServiceAccountEmailPrefix") String cloudSchedulerEmailPrefix) {

    this.tokenVerifier = tokenVerifier;
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
