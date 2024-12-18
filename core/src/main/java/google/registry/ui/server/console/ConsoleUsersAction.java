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

import static com.google.common.base.Strings.isNullOrEmpty;
import static com.google.common.collect.ImmutableList.toImmutableList;
import static google.registry.model.console.RegistrarRole.ACCOUNT_MANAGER;
import static google.registry.persistence.transaction.TransactionManagerFactory.tm;
import static google.registry.request.Action.Method.DELETE;
import static google.registry.request.Action.Method.GET;
import static google.registry.request.Action.Method.POST;
import static google.registry.request.Action.Method.PUT;
import static jakarta.servlet.http.HttpServletResponse.SC_CREATED;
import static jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN;
import static jakarta.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;

import com.google.api.services.directory.Directory;
import com.google.api.services.directory.model.UserName;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.gson.annotations.Expose;
import google.registry.config.RegistryConfig.Config;
import google.registry.model.console.ConsolePermission;
import google.registry.model.console.RegistrarRole;
import google.registry.model.console.User;
import google.registry.model.console.UserRoles;
import google.registry.persistence.VKey;
import google.registry.request.Action;
import google.registry.request.Action.GkeService;
import google.registry.request.HttpException.BadRequestException;
import google.registry.request.Parameter;
import google.registry.request.auth.Auth;
import google.registry.tools.IamClient;
import google.registry.util.StringGenerator;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;

@Action(
    service = Action.GaeService.DEFAULT,
    gkeService = GkeService.CONSOLE,
    path = ConsoleUsersAction.PATH,
    method = {GET, POST, DELETE, PUT},
    auth = Auth.AUTH_PUBLIC_LOGGED_IN)
public class ConsoleUsersAction extends ConsoleApiAction {
  static final String PATH = "/console-api/users";

  private static final int PASSWORD_LENGTH = 16;
  private static final Splitter EMAIL_SPLITTER = Splitter.on('@').trimResults();

  private final String registrarId;
  private final Directory directory;
  private final StringGenerator passwordGenerator;
  private final Optional<UserData> userData;
  private final Optional<String> maybeGroupEmailAddress;
  private final IamClient iamClient;
  private final String gSuiteDomainName;

  @Inject
  public ConsoleUsersAction(
      ConsoleApiParams consoleApiParams,
      Directory directory,
      IamClient iamClient,
      @Config("gSuiteDomainName") String gSuiteDomainName,
      @Config("gSuiteConsoleUserGroupEmailAddress") Optional<String> maybeGroupEmailAddress,
      @Named("base58StringGenerator") StringGenerator passwordGenerator,
      @Parameter("userData") Optional<UserData> userData,
      @Parameter("registrarId") String registrarId) {
    super(consoleApiParams);
    this.registrarId = registrarId;
    this.directory = directory;
    this.passwordGenerator = passwordGenerator;
    this.userData = userData;
    this.maybeGroupEmailAddress = maybeGroupEmailAddress;
    this.iamClient = iamClient;
    this.gSuiteDomainName = gSuiteDomainName;
  }

  @Override
  protected void postHandler(User user) {
    // Temporary flag while testing
    if (user.getUserRoles().isAdmin()) {
      checkPermission(user, registrarId, ConsolePermission.MANAGE_USERS);
      if (userData.isPresent()) { // Adding existing user to registrar
        tm().transact(this::runAppendUserInTransaction);
      } else { // Adding new user to registrar
        tm().transact(this::runCreateInTransaction);
      }

    } else {
      consoleApiParams.response().setStatus(SC_FORBIDDEN);
    }
  }

  @Override
  protected void putHandler(User user) {
    // Temporary flag while testing
    if (user.getUserRoles().isAdmin()) {
      checkPermission(user, registrarId, ConsolePermission.MANAGE_USERS);
      tm().transact(this::runUpdateInTransaction);
    } else {
      consoleApiParams.response().setStatus(SC_FORBIDDEN);
    }
  }

  @Override
  protected void getHandler(User user) {
    checkPermission(user, registrarId, ConsolePermission.MANAGE_USERS);
    List<UserData> users =
        getAllRegistrarUsers(registrarId).stream()
            .map(
                u ->
                    new UserData(
                        u.getEmailAddress(),
                        u.getUserRoles().getRegistrarRoles().get(registrarId).toString(),
                        null))
            .collect(Collectors.toList());

    consoleApiParams.response().setPayload(consoleApiParams.gson().toJson(users));
    consoleApiParams.response().setStatus(SC_OK);
  }

  @Override
  protected void deleteHandler(User user) {
    // Temporary flag while testing
    if (user.getUserRoles().isAdmin()) {
      checkPermission(user, registrarId, ConsolePermission.MANAGE_USERS);
      tm().transact(this::runDeleteInTransaction);
    } else {
      consoleApiParams.response().setStatus(SC_FORBIDDEN);
    }
  }

  private void runAppendUserInTransaction() {
    if (!isModifyingRequestValid(false)) {
      return;
    }
    ImmutableList<User> allRegistrarUsers = getAllRegistrarUsers(registrarId);
    if (allRegistrarUsers.size() >= 4) {
      throw new BadRequestException("Total users amount per registrar is limited to 4");
    }

    updateUserRegistrarRoles(
        this.userData.get().emailAddress,
        registrarId,
        RegistrarRole.valueOf(this.userData.get().role),
        false);
    consoleApiParams.response().setStatus(SC_OK);
  }

  private void runDeleteInTransaction() throws IOException {
    if (!isModifyingRequestValid(true)) {
      return;
    }

    String email = this.userData.get().emailAddress;
    User updatedUser =
        updateUserRegistrarRoles(
            email, registrarId, RegistrarRole.valueOf(this.userData.get().role), true);

    // User has no registrars assigned
    if (updatedUser.getUserRoles().getRegistrarRoles().size() == 0) {
      try {
        directory.users().delete(email).execute();
      } catch (IOException e) {
        setFailedResponse("Failed to delete the user workspace account", SC_INTERNAL_SERVER_ERROR);
        throw e;
      }

      VKey<User> key = VKey.create(User.class, email);
      tm().delete(key);
      User.revokeIapPermission(email, maybeGroupEmailAddress, cloudTasksUtils, null, iamClient);
    }


    consoleApiParams.response().setStatus(SC_OK);
  }

  private void runCreateInTransaction() throws IOException {
    ImmutableList<User> allRegistrarUsers = getAllRegistrarUsers(registrarId);
    if (allRegistrarUsers.size() >= 4) {
      throw new BadRequestException("Total users amount per registrar is limited to 4");
    }

    String nextAvailableEmail =
        IntStream.range(1, 5)
            .mapToObj(i -> String.format("%s-user%s@%s", registrarId, i, gSuiteDomainName))
            .filter(email -> tm().loadByKeyIfPresent(VKey.create(User.class, email)).isEmpty())
            .findFirst()
            // Can only happen if registrar cycled through 20 users, which is unlikely
            .orElseThrow(
                () -> new BadRequestException("Failed to find available increment for new user"));

    com.google.api.services.directory.model.User newUser =
        new com.google.api.services.directory.model.User();

    newUser.setName(
        new UserName()
            .setFamilyName(registrarId)
            .setGivenName(EMAIL_SPLITTER.splitToList(nextAvailableEmail).get(0)));
    newUser.setPassword(passwordGenerator.createString(PASSWORD_LENGTH));
    newUser.setPrimaryEmail(nextAvailableEmail);

    try {
      directory.users().insert(newUser).execute();
    } catch (IOException e) {
      setFailedResponse("Failed to create the user workspace account", SC_INTERNAL_SERVER_ERROR);
      throw e;
    }

    UserRoles userRoles =
        new UserRoles.Builder()
            .setRegistrarRoles(ImmutableMap.of(registrarId, ACCOUNT_MANAGER))
            .build();

    User.Builder builder =
        new User.Builder().setUserRoles(userRoles).setEmailAddress(newUser.getPrimaryEmail());
    tm().put(builder.build());
    User.grantIapPermission(
        nextAvailableEmail, maybeGroupEmailAddress, cloudTasksUtils, null, iamClient);

    consoleApiParams.response().setStatus(SC_CREATED);
    consoleApiParams
        .response()
        .setPayload(
            consoleApiParams
                .gson()
                .toJson(
                    new UserData(
                        newUser.getPrimaryEmail(),
                        ACCOUNT_MANAGER.toString(),
                        newUser.getPassword())));
  }

  private void runUpdateInTransaction() {
    if (!isModifyingRequestValid(true)) {
      return;
    }

    updateUserRegistrarRoles(
        this.userData.get().emailAddress,
        registrarId,
        RegistrarRole.valueOf(this.userData.get().role),
        false);
    consoleApiParams.response().setStatus(SC_OK);
  }

  private boolean isModifyingRequestValid(boolean verifyAccess) {
    if (userData.isEmpty()
        || isNullOrEmpty(userData.get().emailAddress)
        || isNullOrEmpty(userData.get().role)) {
      throw new BadRequestException("User data is missing or incomplete");
    }
    String email = userData.get().emailAddress;
    User userToUpdate =
        tm().loadByKeyIfPresent(VKey.create(User.class, email))
            .orElseThrow(
                () -> new BadRequestException(String.format("User %s doesn't exist", email)));

    if (verifyAccess && !userToUpdate.getUserRoles().getRegistrarRoles().containsKey(registrarId)) {
      setFailedResponse(
          String.format("Can't update user not associated with registrarId %s", registrarId),
          SC_FORBIDDEN);
      return false;
    }
    return true;
  }

  private User updateUserRegistrarRoles(
      String email, String registrarId, RegistrarRole newRole, boolean isDelete) {
    User userToUpdate = tm().loadByKeyIfPresent(VKey.create(User.class, email)).get();
    Map<String, RegistrarRole> updatedRegistrarRoles;
    if (isDelete) {
      updatedRegistrarRoles =
          userToUpdate.getUserRoles().getRegistrarRoles().entrySet().stream()
              .filter(entry -> !Objects.equals(entry.getKey(), registrarId))
              .collect(ImmutableMap.toImmutableMap(Map.Entry::getKey, Map.Entry::getValue));
    } else {
      updatedRegistrarRoles =
          ImmutableMap.<String, RegistrarRole>builder()
              .putAll(userToUpdate.getUserRoles().getRegistrarRoles())
              .put(registrarId, newRole)
              .buildKeepingLast();
    }
    var updatedUser =
        userToUpdate
            .asBuilder()
            .setUserRoles(
                userToUpdate
                    .getUserRoles()
                    .asBuilder()
                    .setRegistrarRoles(updatedRegistrarRoles)
                    .build())
            .build();
    tm().put(updatedUser);
    return updatedUser;
  }

  private ImmutableList<User> getAllRegistrarUsers(String registrarId) {
    return tm().transact(
            () ->
                tm().loadAllOf(User.class).stream()
                    .filter(u -> u.getUserRoles().getRegistrarRoles().containsKey(registrarId))
                    .collect(toImmutableList()));
  }

  public record UserData(
      @Expose String emailAddress, @Expose String role, @Expose @Nullable String password) {}
}
