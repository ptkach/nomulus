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
import static com.google.common.truth.Truth.assertThat;
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
        new ServiceAccountAuthenticationMechanism(tokenVerifier, "sa-prefix@email.com");
    when(request.getHeader(AUTHORIZATION)).thenReturn("Bearer jwtValue");
    Payload payload = new Payload();
    payload.setEmail("sa-prefix@email.com");
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

  @Test
  void testFails_authenticateWrongHeader() throws Exception {
    when(request.getHeader(AUTHORIZATION)).thenReturn("BEARER asd");
    AuthResult authResult = serviceAccountAuthenticationMechanism.authenticate(request);
    assertThat(authResult.isAuthenticated()).isFalse();
  }
}
