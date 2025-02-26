// Copyright 2019 The Nomulus Authors. All Rights Reserved.
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

package google.registry.sql.flyway;

import static com.google.common.truth.Truth.assertThat;
import static google.registry.testing.truth.TextDiffSubject.assertThat;

import com.google.common.base.Joiner;
import com.google.common.flogger.FluentLogger;
import com.google.common.io.Resources;
import google.registry.persistence.NomulusPostgreSql;
import java.io.File;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import org.flywaydb.core.Flyway;
import org.flywaydb.database.postgresql.PostgreSQLConfigurationExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledIfSystemProperty;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Schema deployment tests using Flyway.
 *
 * <p>This class has two test methods:
 *
 * <ul>
 *   <li>{@link #deploySchema_emptyDb()} is invoked only in UNIT tests (:db:test in Gradle). It
 *       deploys the entire set of Flyway scripts (found on classpath) to an empty database and
 *       compares the resulting schema with the golden schema.
 *   <li>{@link #deploySchema_existingDb()} is invoked only in an integration test
 *       (:db:schemaIncrementalDeployTest in Gradle). It first populates the test database with an
 *       earlier release of the schema (found on the classpath), then deploys the latest Flyway
 *       scripts (found on local filesystem under the resources directory) to that database. This
 *       test detects all forbidden changes to deployed scripts including content change, file
 *       renaming, and file deletion.
 *       <p>This test also checks for out-of-order version numbers, i.e., new scripts with lower
 *       numbers than that of the last deployed script. Out-of-order versions are confusing to
 *       maintainers, however, Flyway does not provide ways to check before schema deployment. In
 *       this test, out-of-order scripts are ignored in the incremental-deployment phase (default
 *       Flyway behavior). The final validate call will fail on them.
 * </ul>
 */
@Testcontainers
class SchemaTest {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  // Resource path that is mapped to the testcontainer instance.
  private static final String MOUNTED_RESOURCE_PATH = "testcontainer/mount";
  // The mount point in the container.
  private static final String CONTAINER_MOUNT_POINT = "/tmp/pg_dump_out";
  // pg_dump output file name.
  private static final String DUMP_OUTPUT_FILE = "dump.txt";

  /**
   * The target database for schema deployment.
   *
   * <p>A resource path is mapped to this container in READ_WRITE mode to retrieve the deployed
   * schema generated by the 'pg_dump' command. Compared with communicating over stdout, it is
   * easier to update the golden schema this way.
   */
  @Container
  private final PostgreSQLContainer<?> sqlContainer =
      new PostgreSQLContainer<>(NomulusPostgreSql.getDockerImageName())
          .withClasspathResourceMapping(
              MOUNTED_RESOURCE_PATH, CONTAINER_MOUNT_POINT, BindMode.READ_WRITE);

  @Test
  @DisabledIfSystemProperty(named = "deploy_to_existing_db", matches = ".*")
  void deploySchema_emptyDb() throws Exception {
    Flyway flyway =
        Flyway.configure()
            .locations("sql/flyway")
            .dataSource(
                sqlContainer.getJdbcUrl(), sqlContainer.getUsername(), sqlContainer.getPassword())
            .load();

    PostgreSQLConfigurationExtension configurationExtension =
        flyway.getConfigurationExtension(PostgreSQLConfigurationExtension.class);
    configurationExtension.setTransactionalLock(false);

    // flyway.migrate() returns the number of newly pushed scripts. This is a variable
    // number as our schema evolves.
    assertThat(flyway.migrate().migrations).isNotEmpty();
    flyway.validate();

    ExecResult execResult =
        sqlContainer.execInContainer(
            StandardCharsets.UTF_8,
            getSchemaDumpCommand(sqlContainer.getUsername(), sqlContainer.getDatabaseName()));
    if (execResult.getExitCode() != 0) {
      throw new RuntimeException(execResult.toString());
    }

    URL dumpedSchema =
        Resources.getResource(
            Joiner.on(File.separatorChar).join(MOUNTED_RESOURCE_PATH, DUMP_OUTPUT_FILE));

    assertThat(dumpedSchema)
        .ignoringLinesStartingWith("--")
        .hasSameContentAs(Resources.getResource("sql/schema/nomulus.golden.sql"));
  }

  @Test
  @EnabledIfSystemProperty(named = "deploy_to_existing_db", matches = ".*")
  void deploySchema_existingDb() {
    // Initialize the database with the base schema, which is on the classpath.
    Flyway flyway =
        Flyway.configure()
            .locations("sql/flyway")
            .dataSource(
                sqlContainer.getJdbcUrl(), sqlContainer.getUsername(), sqlContainer.getPassword())
            .load();
    PostgreSQLConfigurationExtension configurationExtension =
        flyway.getConfigurationExtension(PostgreSQLConfigurationExtension.class);
    configurationExtension.setTransactionalLock(false);

    flyway.migrate();
    logger.atInfo().log("Base schema version: %s", flyway.info().current().getVersion());

    // Deploy latest scripts from resources directory.
    flyway =
        Flyway.configure()
            .locations("filesystem:build/resources/main/sql/flyway")
            .dataSource(
                sqlContainer.getJdbcUrl(), sqlContainer.getUsername(), sqlContainer.getPassword())
            .load();
    configurationExtension =
        flyway.getConfigurationExtension(PostgreSQLConfigurationExtension.class);
    configurationExtension.setTransactionalLock(false);
    flyway.migrate();
    flyway.validate();
    logger.atInfo().log("Latest schema version: %s", flyway.info().current().getVersion());
  }

  private static String[] getSchemaDumpCommand(String username, String dbName) {
    return new String[] {
      "pg_dump",
      "-h",
      "localhost",
      "-U",
      username,
      "-f",
      Paths.get(CONTAINER_MOUNT_POINT, DUMP_OUTPUT_FILE).toString(),
      "--schema-only",
      "--no-owner",
      "--no-privileges",
      "--exclude-table",
      "flyway_schema_history",
      dbName
    };
  }
}
