// Copyright 2024 The Nomulus Authors. All Rights Reserved.
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

package google.registry.ui.server.console;

import static com.google.common.truth.Truth.assertThat;
import static google.registry.model.registrar.RegistrarPoc.Type.WHOIS;
import static google.registry.testing.DatabaseHelper.createTlds;
import static google.registry.testing.DatabaseHelper.loadSingleton;
import static google.registry.testing.DatabaseHelper.persistResource;
import static jakarta.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import google.registry.model.console.ConsoleUpdateHistory;
import google.registry.model.console.GlobalRole;
import google.registry.model.console.User;
import google.registry.model.console.UserRoles;
import google.registry.model.registrar.Registrar;
import google.registry.model.registrar.RegistrarPoc;
import google.registry.request.Action;
import google.registry.request.RequestModule;
import google.registry.request.auth.AuthResult;
import google.registry.testing.ConsoleApiParamsUtils;
import google.registry.testing.SystemPropertyExtension;
import google.registry.util.EmailMessage;
import google.registry.util.RegistryEnvironment;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Optional;
import org.joda.time.DateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

/** Tests for {@link google.registry.ui.server.console.ConsoleUpdateRegistrarAction}. */
class ConsoleUpdateRegistrarActionTest extends ConsoleActionBaseTestCase {

  private Registrar registrar;

  private User user;

  private static String registrarPostData =
      "{\"registrarId\":\"%s\",\"allowedTlds\":[%s],\"registryLockAllowed\":%s,"
          + " \"lastPocVerificationDate\":%s }";

  @RegisterExtension
  @Order(Integer.MAX_VALUE)
  final SystemPropertyExtension systemPropertyExtension = new SystemPropertyExtension();

  @BeforeEach
  void beforeEach() throws Exception {
    createTlds("app", "dev");
    registrar = Registrar.loadByRegistrarId("TheRegistrar").get();
    persistResource(
        registrar
            .asBuilder()
            .setType(Registrar.Type.REAL)
            .setAllowedTlds(ImmutableSet.of())
            .setRegistryLockAllowed(false)
            .build());
    user =
        persistResource(
            new User.Builder()
                .setEmailAddress("user@registrarId.com")
                .setUserRoles(new UserRoles.Builder().setGlobalRole(GlobalRole.FTE).build())
                .build());
  }

  @Test
  void testSuccess_updatesRegistrar() throws IOException {
    var action =
        createAction(
            String.format(
                registrarPostData,
                "TheRegistrar",
                "app, dev",
                false,
                "\"2023-12-12T00:00:00.000Z\""));
    action.run();
    Registrar newRegistrar = Registrar.loadByRegistrarId("TheRegistrar").get();
    assertThat(newRegistrar.getAllowedTlds()).containsExactly("app", "dev");
    assertThat(newRegistrar.isRegistryLockAllowed()).isFalse();
    assertThat(response.getStatus()).isEqualTo(SC_OK);
    ConsoleUpdateHistory history = loadSingleton(ConsoleUpdateHistory.class).get();
    assertThat(history.getType()).isEqualTo(ConsoleUpdateHistory.Type.REGISTRAR_UPDATE);
    assertThat(history.getDescription()).hasValue("TheRegistrar");
  }

  @Test
  void testSuccess_updatesNullPocVerificationDate() throws IOException {
    var action =
        createAction(
            String.format(registrarPostData, "TheRegistrar", "app, dev", false, "\"null\""));
    action.run();
    Registrar newRegistrar = Registrar.loadByRegistrarId("TheRegistrar").get();
    assertThat(newRegistrar.getLastPocVerificationDate())
        .isEqualTo(DateTime.parse("1970-01-01T00:00:00.000Z"));
  }

  @Test
  void testFailure_pocVerificationInTheFuture() throws IOException {
    var action =
        createAction(
            String.format(
                registrarPostData,
                "TheRegistrar",
                "app, dev",
                false,
                "\"2025-02-01T00:00:00.000Z\""));
    action.run();
    assertThat(response.getStatus()).isEqualTo(SC_BAD_REQUEST);
    assertThat((String) response.getPayload())
        .contains("Invalid value of LastPocVerificationDate - value is in the future");
  }

  @Test
  void testFails_missingWhoisContact() throws IOException {
    RegistryEnvironment.PRODUCTION.setup(systemPropertyExtension);
    var action =
        createAction(
            String.format(
                registrarPostData,
                "TheRegistrar",
                "app, dev",
                false,
                "\"2024-12-12T00:00:00.000Z\""));
    action.run();
    assertThat(response.getStatus()).isEqualTo(SC_BAD_REQUEST);
    assertThat((String) response.getPayload())
        .contains("Cannot modify allowed TLDs if there is no WHOIS abuse contact set");
  }

  @Test
  void testSuccess_presentWhoisContact() throws IOException {
    RegistryEnvironment.PRODUCTION.setup(systemPropertyExtension);
    RegistrarPoc contact =
        new RegistrarPoc.Builder()
            .setRegistrar(registrar)
            .setName("Test Registrar 1")
            .setEmailAddress("test.registrar1@example.com")
            .setPhoneNumber("+1.9999999999")
            .setFaxNumber("+1.9999999991")
            .setTypes(ImmutableSet.of(WHOIS))
            .setVisibleInWhoisAsAdmin(true)
            .setVisibleInWhoisAsTech(true)
            .setVisibleInDomainWhoisAsAbuse(true)
            .build();
    persistResource(contact);
    var action =
        createAction(
            String.format(
                registrarPostData,
                "TheRegistrar",
                "app, dev",
                false,
                "\"2023-12-12T00:00:00.000Z\""));
    action.run();
    Registrar newRegistrar = Registrar.loadByRegistrarId("TheRegistrar").get();
    assertThat(newRegistrar.getAllowedTlds()).containsExactly("app", "dev");
    assertThat(newRegistrar.isRegistryLockAllowed()).isFalse();
    assertThat(response.getStatus()).isEqualTo(SC_OK);
  }

  @Test
  void testSuccess_sendsEmail() throws AddressException, IOException {
    var action =
        createAction(
            String.format(
                registrarPostData,
                "TheRegistrar",
                "app, dev",
                false,
                "\"2023-12-12T00:00:00.000Z\""));
    action.run();
    verify(consoleApiParams.sendEmailUtils().gmailClient, times(1))
        .sendEmail(
            EmailMessage.newBuilder()
                .setSubject(
                    "Registrar The Registrar (TheRegistrar) updated in registry unittest"
                        + " environment")
                .setBody(
                    "The following changes were made in registry unittest environment to the"
                        + " registrar TheRegistrar by admin fte@email.tld:\n"
                        + "\n"
                        + "allowedTlds: null -> [app, dev]\n"
                        + "lastPocVerificationDate: 1970-01-01T00:00:00.000Z ->"
                        + " 2023-12-12T00:00:00.000Z\n")
                .setRecipients(ImmutableList.of(new InternetAddress("notification@test.example")))
                .build());
  }

  private ConsoleApiParams createParams() {
    AuthResult authResult = AuthResult.createUser(user);
    return ConsoleApiParamsUtils.createFake(authResult);
  }

  private ConsoleUpdateRegistrarAction createAction(String requestData) throws IOException {
    when(consoleApiParams.request().getMethod()).thenReturn(Action.Method.POST.toString());
    doReturn(new BufferedReader(new StringReader(requestData)))
        .when(consoleApiParams.request())
        .getReader();
    Optional<Registrar> maybeRegistrarUpdateData =
        ConsoleModule.provideRegistrar(
            GSON, RequestModule.provideJsonBody(consoleApiParams.request(), GSON));
    return new ConsoleUpdateRegistrarAction(consoleApiParams, maybeRegistrarUpdateData);
  }
}
