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

package google.registry.flows;

import static google.registry.xml.XmlTransformer.prettyPrint;

import com.google.common.flogger.FluentLogger;
import google.registry.flows.FlowModule.DryRun;
import google.registry.flows.FlowModule.InputXml;
import google.registry.flows.FlowModule.LogSqlStatements;
import google.registry.flows.FlowModule.RegistrarId;
import google.registry.flows.FlowModule.Superuser;
import google.registry.flows.FlowModule.Transactional;
import google.registry.flows.session.LoginFlow;
import google.registry.model.eppcommon.Trid;
import google.registry.model.eppoutput.EppOutput;
import google.registry.monitoring.whitebox.EppMetric;
import google.registry.persistence.PersistenceModule.TransactionIsolationLevel;
import google.registry.persistence.transaction.JpaTransactionManager;
import jakarta.inject.Inject;
import jakarta.inject.Provider;
import java.util.Optional;

/** Run a flow, either transactionally or not, with logging and retrying as needed. */
public class FlowRunner {

  private static final String COMMAND_LOG_FORMAT = "EPP Command" + "\n\t%s".repeat(8);

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  @Inject @RegistrarId String registrarId;
  @Inject TransportCredentials credentials;
  @Inject EppRequestSource eppRequestSource;
  @Inject Provider<Flow> flowProvider;
  @Inject Optional<TransactionIsolationLevel> isolationLevelOverride;
  @Inject Class<? extends Flow> flowClass;
  @Inject @InputXml byte[] inputXmlBytes;
  @Inject @DryRun boolean isDryRun;
  @Inject @Superuser boolean isSuperuser;
  @Inject @Transactional boolean isTransactional;
  @Inject @LogSqlStatements boolean logSqlStatements;
  @Inject SessionMetadata sessionMetadata;
  @Inject Trid trid;
  @Inject FlowReporter flowReporter;
  @Inject JpaTransactionManager jpaTransactionManager;

  @Inject FlowRunner() {}

  /** Runs the EPP flow, and records metrics on the given builder. */
  public EppOutput run(final EppMetric.Builder eppMetricBuilder) throws EppException {
    String prettyXml = prettyPrint(EppXmlSanitizer.sanitizeEppXml(inputXmlBytes));

    logger.atInfo().log(
        COMMAND_LOG_FORMAT,
        trid.getServerTransactionId(),
        registrarId,
        sessionMetadata,
        prettyXml.replace("\n", "\n\t"),
        credentials,
        eppRequestSource,
        isDryRun ? "DRY_RUN" : "LIVE",
        isSuperuser ? "SUPERUSER" : "NORMAL");
    // Record flow info to the GAE request logs for reporting purposes if it's not a dry run.
    if (!isDryRun) {
      flowReporter.recordToLogs();
    }
    eppMetricBuilder.setCommandNameFromFlow(flowClass.getSimpleName());
    // We may already be in a transaction, e.g., when invoked by DeleteExpiredDomainsAction.
    if (!isTransactional || jpaTransactionManager.inTransaction()) {
      return EppOutput.create(flowProvider.get().run());
    }
    try {
      return jpaTransactionManager.transact(
          isolationLevelOverride.orElse(null),
          () -> {
            try {
              EppOutput output = EppOutput.create(flowProvider.get().run());
              if (isDryRun) {
                throw new DryRunException(output);
              }
              if (flowClass.equals(LoginFlow.class)) {
                // In LoginFlow, registrarId isn't known until after the flow executes, so save
                // it then.
                eppMetricBuilder.setRegistrarId(sessionMetadata.getRegistrarId());
              }
              return output;
            } catch (EppException e) {
              throw new EppRuntimeException(e);
            }
          },
          logSqlStatements);
    } catch (DryRunException e) {
      return e.output;
    } catch (EppRuntimeException e) {
      throw e.getCause();
    }
  }

  /** Exception for canceling a transaction while capturing what the output would have been. */
  private static class DryRunException extends RuntimeException {
    final EppOutput output;

    DryRunException(EppOutput output) {
      this.output = output;
    }
  }

  /**
   * Exception for explicitly propagating an EppException out of the transactional {@code Supplier}.
   */
  private static class EppRuntimeException extends RuntimeException {
    EppRuntimeException(EppException cause) {
      super(cause);
    }

    @Override
    public synchronized EppException getCause() {
      return (EppException) super.getCause();
    }
  }
}
