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

package google.registry.ui.server.console.domains;

import static com.google.common.truth.Truth.assertThat;
import static google.registry.model.common.FeatureFlag.FeatureName.MINIMUM_DATASET_CONTACTS_OPTIONAL;
import static google.registry.model.common.FeatureFlag.FeatureStatus.INACTIVE;
import static google.registry.testing.DatabaseHelper.loadByEntity;
import static google.registry.testing.DatabaseHelper.loadSingleton;
import static google.registry.testing.DatabaseHelper.persistActiveContact;
import static google.registry.testing.DatabaseHelper.persistDomainWithDependentResources;
import static google.registry.testing.DatabaseHelper.persistResource;
import static google.registry.util.DateTimeUtils.START_OF_TIME;
import static jakarta.servlet.http.HttpServletResponse.SC_BAD_REQUEST;
import static jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.ImmutableSortedMap;
import com.google.gson.JsonElement;
import google.registry.flows.DaggerEppTestComponent;
import google.registry.flows.EppController;
import google.registry.flows.EppTestComponent;
import google.registry.model.common.FeatureFlag;
import google.registry.model.console.ConsoleUpdateHistory;
import google.registry.model.console.RegistrarRole;
import google.registry.model.console.User;
import google.registry.model.console.UserRoles;
import google.registry.model.domain.Domain;
import google.registry.model.eppcommon.StatusValue;
import google.registry.request.auth.AuthResult;
import google.registry.testing.ConsoleApiParamsUtils;
import google.registry.testing.FakeResponse;
import google.registry.ui.server.console.ConsoleActionBaseTestCase;
import google.registry.ui.server.console.ConsoleApiParams;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Tests for {@link ConsoleBulkDomainAction}. */
public class ConsoleBulkDomainActionTest extends ConsoleActionBaseTestCase {

  private static ImmutableSet<StatusValue> serverSuspensionStatuses =
      ImmutableSet.of(
          StatusValue.SERVER_RENEW_PROHIBITED,
          StatusValue.SERVER_TRANSFER_PROHIBITED,
          StatusValue.SERVER_UPDATE_PROHIBITED,
          StatusValue.SERVER_DELETE_PROHIBITED,
          StatusValue.SERVER_HOLD);

  private EppController eppController;
  private Domain domain;

  @BeforeEach
  void beforeEach() {
    persistResource(
        new FeatureFlag()
            .asBuilder()
            .setFeatureName(MINIMUM_DATASET_CONTACTS_OPTIONAL)
            .setStatusMap(ImmutableSortedMap.of(START_OF_TIME, INACTIVE))
            .build());
    eppController =
        DaggerEppTestComponent.builder()
            .fakesAndMocksModule(EppTestComponent.FakesAndMocksModule.create(clock))
            .build()
            .startRequest()
            .eppController();
    domain =
        persistDomainWithDependentResources(
            "example",
            "tld",
            persistActiveContact("contact1234"),
            clock.nowUtc(),
            clock.nowUtc().minusMonths(1),
            clock.nowUtc().plusMonths(11));
  }

  @Test
  void testSuccess_delete() {
    ConsoleBulkDomainAction action =
        createAction(
            "DELETE",
            GSON.toJsonTree(
                ImmutableMap.of("domainList", ImmutableList.of("example.tld"), "reason", "test")));
    action.run();
    assertThat(response.getStatus()).isEqualTo(SC_OK);
    assertThat(response.getPayload())
        .isEqualTo(
            """
{"example.tld":{"message":"Command completed successfully; action pending",\
"responseCode":1001}}""");
    assertThat(loadByEntity(domain).getDeletionTime()).isEqualTo(clock.nowUtc().plusDays(35));
    ConsoleUpdateHistory history = loadSingleton(ConsoleUpdateHistory.class).get();
    assertThat(history.getType()).isEqualTo(ConsoleUpdateHistory.Type.DOMAIN_DELETE);
    assertThat(history.getDescription()).hasValue("example.tld");
  }

  @Test
  void testSuccess_suspend() throws Exception {
    ConsoleBulkDomainAction action =
        createAction(
            "SUSPEND",
            GSON.toJsonTree(
                ImmutableMap.of("domainList", ImmutableList.of("example.tld"), "reason", "test")));
    action.run();
    assertThat(response.getStatus()).isEqualTo(SC_OK);
    assertThat(response.getPayload())
        .isEqualTo(
            """
            {"example.tld":{"message":"Command completed successfully","responseCode":1000}}""");
    assertThat(loadByEntity(domain).getStatusValues())
        .containsAtLeastElementsIn(serverSuspensionStatuses);
    ConsoleUpdateHistory history = loadSingleton(ConsoleUpdateHistory.class).get();
    assertThat(history.getType()).isEqualTo(ConsoleUpdateHistory.Type.DOMAIN_SUSPEND);
    assertThat(history.getDescription()).hasValue("example.tld");
  }

  @Test
  void testSuccess_unsuspend() throws Exception {
    persistResource(domain.asBuilder().addStatusValues(serverSuspensionStatuses).build());
    ConsoleBulkDomainAction action =
        createAction(
            "UNSUSPEND",
            GSON.toJsonTree(
                ImmutableMap.of("domainList", ImmutableList.of("example.tld"), "reason", "test")));
    assertThat(loadByEntity(domain).getStatusValues())
        .containsAtLeastElementsIn(serverSuspensionStatuses);
    action.run();
    assertThat(response.getStatus()).isEqualTo(SC_OK);
    assertThat(response.getPayload())
        .isEqualTo(
            """
            {"example.tld":{"message":"Command completed successfully","responseCode":1000}}""");
    assertThat(loadByEntity(domain).getStatusValues()).containsNoneIn(serverSuspensionStatuses);
    ConsoleUpdateHistory history = loadSingleton(ConsoleUpdateHistory.class).get();
    assertThat(history.getType()).isEqualTo(ConsoleUpdateHistory.Type.DOMAIN_UNSUSPEND);
    assertThat(history.getDescription()).hasValue("example.tld");
  }

  @Test
  void testHalfSuccess_halfNonexistent() throws Exception {
    ConsoleBulkDomainAction action =
        createAction(
            "DELETE",
            GSON.toJsonTree(
                ImmutableMap.of(
                    "domainList",
                    ImmutableList.of("example.tld", "nonexistent.tld"),
                    "reason",
                    "test")));
    action.run();
    assertThat(response.getStatus()).isEqualTo(SC_OK);
    assertThat(response.getPayload())
        .isEqualTo(
            """
{"example.tld":{"message":"Command completed successfully; action pending","responseCode":1001},\
"nonexistent.tld":{"message":"The domain with given ID (nonexistent.tld) doesn\\u0027t exist.",\
"responseCode":2303}}""");
    assertThat(loadByEntity(domain).getDeletionTime()).isEqualTo(clock.nowUtc().plusDays(35));
    ConsoleUpdateHistory history = loadSingleton(ConsoleUpdateHistory.class).get();
    assertThat(history.getType()).isEqualTo(ConsoleUpdateHistory.Type.DOMAIN_DELETE);
    assertThat(history.getDescription()).hasValue("example.tld");
  }

  @Test
  void testFailure_badActionString() {
    ConsoleBulkDomainAction action = createAction("bad", GSON.toJsonTree(ImmutableMap.of()));
    action.run();
    assertThat(response.getStatus()).isEqualTo(SC_BAD_REQUEST);
    assertThat(response.getPayload())
        .isEqualTo(
            "No enum constant"
                + " google.registry.ui.server.console.domains.ConsoleDomainActionType.BulkAction.bad");
  }

  @Test
  void testFailure_emptyBody() {
    ConsoleBulkDomainAction action = createAction("DELETE", null);
    action.run();
    assertThat(response.getStatus()).isEqualTo(SC_BAD_REQUEST);
    assertThat(response.getPayload()).isEqualTo("Bulk action payload must be present");
  }

  @Test
  void testFailure_noPermission() {
    JsonElement payload =
        GSON.toJsonTree(
            ImmutableMap.of("domainList", ImmutableList.of("domain.tld"), "reason", "reason"));
    ConsoleBulkDomainAction action =
        createAction(
            "DELETE",
            payload,
            new User.Builder()
                .setEmailAddress("foobar@theregistrar.com")
                .setUserRoles(
                    new UserRoles.Builder()
                        .setRegistrarRoles(
                            ImmutableMap.of("TheRegistrar", RegistrarRole.ACCOUNT_MANAGER))
                        .build())
                .build());
    action.run();
    assertThat(response.getStatus()).isEqualTo(SC_FORBIDDEN);
  }

  // @ptkach - reenable with suspend change
  // @Test
  // void testFailure_suspend_nonAdmin() {
  //   ConsoleBulkDomainAction action =
  //       createAction(
  //           "SUSPEND",
  //           GSON.toJsonTree(
  //               ImmutableMap.of("domainList", ImmutableList.of("example.tld"), "reason",
  // "test")),
  //           user);
  //   action.run();
  //   assertThat(fakeResponse.getStatus()).isEqualTo(SC_OK);
  //   Map<String, ConsoleBulkDomainAction.ConsoleEppOutput> payload =
  //       GSON.fromJson(fakeResponse.getPayload(), new TypeToken<>() {});
  //   assertThat(payload).containsKey("example.tld");
  //   assertThat(payload.get("example.tld").responseCode()).isEqualTo(2004);
  //   assertThat(payload.get("example.tld").message()).contains("cannot be set by clients");
  //   assertThat(loadByEntity(domain)).isEqualTo(domain);
  // }

  private ConsoleBulkDomainAction createAction(String action, JsonElement payload) {
    return createAction(action, payload, fteUser);
  }

  private ConsoleBulkDomainAction createAction(String action, JsonElement payload, User user) {
    AuthResult authResult = AuthResult.createUser(user);
    ConsoleApiParams params = ConsoleApiParamsUtils.createFake(authResult);
    when(params.request().getMethod()).thenReturn("POST");
    response = (FakeResponse) params.response();
    return new ConsoleBulkDomainAction(
        params, eppController, "TheRegistrar", action, Optional.ofNullable(payload));
  }
}
