// Copyright 2017 The Nomulus Authors. All Rights Reserved.
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

package google.registry.tools;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.collect.ImmutableSet.toImmutableSet;
import static google.registry.model.eppcommon.StatusValue.SERVER_DELETE_PROHIBITED;
import static google.registry.model.eppcommon.StatusValue.SERVER_TRANSFER_PROHIBITED;
import static google.registry.model.eppcommon.StatusValue.SERVER_UPDATE_PROHIBITED;
import static google.registry.util.CollectionUtils.findDuplicates;

import com.beust.jcommander.Parameter;
import com.google.common.base.Joiner;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.flogger.FluentLogger;
import google.registry.config.RegistryConfig.Config;
import google.registry.model.eppcommon.StatusValue;
import jakarta.inject.Inject;
import java.util.List;

/** Shared base class for commands to registry lock or unlock a domain via EPP. */
public abstract class LockOrUnlockDomainCommand extends ConfirmingCommand {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  public static final ImmutableSet<StatusValue> REGISTRY_LOCK_STATUSES =
      ImmutableSet.of(
          SERVER_DELETE_PROHIBITED, SERVER_TRANSFER_PROHIBITED, SERVER_UPDATE_PROHIBITED);

  @Parameter(
      names = {"-c", "--client"},
      description =
          "Client ID of the requesting registrar if applicable, otherwise the registry registrar")
  String clientId;

  @Parameter(description = "Names of the domains", required = true)
  private List<String> mainParameters;

  @Inject
  @Config("registryAdminClientId")
  String registryAdminClientId;

  @Inject DomainLockUtils domainLockUtils;

  protected ImmutableSet<String> getDomains() {
    return ImmutableSet.copyOf(mainParameters);
  }

  @Override
  protected void init() {
    // Default clientId to the registry registrar account if otherwise unspecified.
    if (clientId == null) {
      clientId = registryAdminClientId;
    }
    String duplicates = Joiner.on(", ").join(findDuplicates(mainParameters));
    checkArgument(duplicates.isEmpty(), "Duplicate domain arguments found: '%s'", duplicates);
    printStream.println(
        "== ENSURE THAT YOU HAVE AUTHENTICATED THE REGISTRAR BEFORE RUNNING THIS COMMAND ==");
  }

  @Override
  protected String execute() {
    ImmutableSet.Builder<String> successfulDomainsBuilder = new ImmutableSet.Builder<>();
    ImmutableMap.Builder<String, String> failedDomainsToReasons = new ImmutableMap.Builder<>();
    for (String domain : getDomains()) {
      try {
        createAndApplyRequest(domain);
      } catch (Throwable t) {
        logger.atSevere().withCause(t).log("Error when (un)locking domain %s.", domain);
        failedDomainsToReasons.put(domain, t.getMessage());
        continue;
      }
      successfulDomainsBuilder.add(domain);
    }
    ImmutableSet<String> successfulDomains = successfulDomainsBuilder.build();
    ImmutableSet<String> failedDomains =
        failedDomainsToReasons.build().entrySet().stream()
            .map(entry -> String.format("%s (%s)", entry.getKey(), entry.getValue()))
            .collect(toImmutableSet());
    return String.format(
        "Successfully locked/unlocked domains:\n%s\nFailed domains:\n%s",
        successfulDomains, failedDomains);
  }

  protected abstract void createAndApplyRequest(String domain);
}
