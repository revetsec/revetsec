/*
 * Copyright 2026 Revetware LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package verification.migration;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Base64;
import java.util.Properties;
import org.jspecify.annotations.NonNull;

/** One bounded owned-fixture transaction; no SQL, state, password or JDBC diagnostics escape. */
public final class PgBatch {
    private PgBatch() { }
    public static void main(@NonNull String @NonNull [] args) {
        boolean possible = false, committing = false;
        Connection connection = null;
        try {
            Properties properties = new Properties();
            properties.setProperty("user", System.getenv("DB_USER"));
            properties.setProperty("password", System.getenv("DB_PASSWORD"));
            properties.setProperty("sslmode", "disable");
            properties.setProperty("gssEncMode", "disable");
            properties.setProperty("preferQueryMode", "simple");
            properties.setProperty("connectTimeout", "3");
            properties.setProperty("socketTimeout", "10");
            properties.setProperty("ApplicationName", "scp10-batch");
            connection = DriverManager.getConnection(System.getenv("DB_URL"), properties);
            connection.setAutoCommit(false);
            try (Statement statement = connection.createStatement()) {
                statement.execute("SET LOCAL statement_timeout='8000ms'");
                statement.execute("SET LOCAL lock_timeout='3000ms'");
                BufferedReader input = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII));
                String line;int total=0,count=0;
                while ((line=input.readLine())!=null) {
                    total += line.length();count++;
                    if (total>16000000 || count>1600) throw new SQLException("Bounded fixture input");
                    String sql=new String(Base64.getDecoder().decode(line),StandardCharsets.UTF_8);
                    possible=true;statement.execute(sql);
                }
            }
            committing=true;connection.commit();System.out.println("COMMITTED");
        } catch (Exception failure) {
            boolean rolledBack=false;
            if (!committing && connection!=null) try {connection.rollback();rolledBack=true;} catch (SQLException ignored) { }
            System.out.println(!possible || rolledBack ? "NO_EFFECT" : "UNKNOWN");
        } finally {
            if (connection!=null) try {connection.close();} catch (SQLException ignored) { }
        }
    }
}
