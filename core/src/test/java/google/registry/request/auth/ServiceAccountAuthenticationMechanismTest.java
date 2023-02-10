package google.registry.request.auth;

import static com.google.common.net.HttpHeaders.AUTHORIZATION;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.json.webtoken.JsonWebSignature;
import com.google.api.client.json.webtoken.JsonWebSignature.Header;
import com.google.auth.oauth2.TokenVerifier;
import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ServiceAccountAuthenticationMechanismTest {

  @Mock private TokenVerifier tokenVerifier;
  @Mock private HttpServletRequest request;

  private JsonWebSignature token;
  private ServiceAccountAuthenticationMechanism serviceAccountAuthenticationMechanism;

  @BeforeEach
  void beforeEach() throws Exception {
    serviceAccountAuthenticationMechanism =
        new ServiceAccountAuthenticationMechanism(tokenVerifier, "testProject", "sa-prefix@");
    when(request.getHeader(AUTHORIZATION)).thenReturn("Bearer jwtValue");
    Payload payload = new Payload();
    payload.setEmail("sa-prefix@email.com");
    payload.setSubject("gaiaId");
    token = new JsonWebSignature(new Header(), payload, new byte[0], new byte[0]);
    when(tokenVerifier.verify("jwtValue")).thenReturn(token);
  }

  @Test
  void testSuccess_authenticates() throws Exception {
    AuthResult authResult = serviceAccountAuthenticationMechanism.authenticate(request);
    assertThat(authResult.isAuthenticated()).isTrue();
    assertThat(authResult.authLevel()).isEqualTo(AuthLevel.APP);
  }

  @Test
  void testFails_authenticateWrongEmail() throws Exception {
    token.getPayload().set("email", "not-service-account-email@email.com");
    AuthResult authResult = serviceAccountAuthenticationMechanism.authenticate(request);
    assertThat(authResult.isAuthenticated()).isFalse();
  }
}
