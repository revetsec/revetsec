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

package verification.store;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import javax.sql.DataSource;
import java.io.PrintWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.*;
import java.util.Properties;
import java.util.logging.Logger;

/** Application-owned unpooled fixture source: every driver operation shares the original absolute deadline.
 * The connection facade updates the physical driver's network timeout before each operation, including COMMIT.
 * No logger, mutable global login timeout, owned thread, or automatic retry. */
final class BudgetDataSource implements DataSource {
    private final @NonNull String url;
    private final @NonNull Properties properties;
    private final long deadline;
    BudgetDataSource(@NonNull String url,@NonNull Properties properties,long deadline) {
        this.url=url;this.properties=new Properties();this.properties.putAll(properties);this.deadline=deadline;
    }
    @Override public @NonNull Connection getConnection() throws SQLException {
        Properties p=new Properties();p.putAll(this.properties);int ms=PostgresStore.millis(this.deadline);
        p.setProperty("connectTimeout",Integer.toString(Math.max(1,(ms+999)/1000)));
        p.setProperty("socketTimeout",Integer.toString(Math.max(1,(ms+999)/1000)));
        p.setProperty("preferQueryMode","simple");p.setProperty("sslmode","disable");p.setProperty("gssEncMode","disable");
        Connection physical=DriverManager.getConnection(this.url,p);
        try {
            physical.setNetworkTimeout(Runnable::run,PostgresStore.millis(this.deadline));
            return (Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},
                new java.lang.reflect.InvocationHandler() {
                    @Override public @Nullable Object invoke(@NonNull Object proxy,@NonNull Method method,@Nullable Object @Nullable [] arguments) throws Throwable {
                        String name=method.getName();
                        // Cleanup remains possible after expiry; never turn close/rollback into an authorizing retry.
                        if (!name.equals("close") && !name.equals("rollback") && !name.equals("isClosed") && !name.equals("abort"))
                            physical.setNetworkTimeout(Runnable::run,PostgresStore.millis(BudgetDataSource.this.deadline));
                        try {return method.invoke(physical,arguments);}catch(InvocationTargetException e){throw e.getCause();}
                    }
                });
        } catch (SQLException | RuntimeException e) {try{physical.close();}catch(SQLException ignored) { }throw e;}
    }
    @Override public @NonNull Connection getConnection(@Nullable String user,@Nullable String password) throws SQLException {throw new SQLFeatureNotSupportedException("Fixed fixture credentials");}
    @Override public @Nullable PrintWriter getLogWriter() {return null;}
    @Override public void setLogWriter(@Nullable PrintWriter writer) throws SQLException {throw new SQLFeatureNotSupportedException("No credential logging");}
    @Override public void setLoginTimeout(int seconds) throws SQLException {throw new SQLFeatureNotSupportedException("Fixed deadline");}
    @Override public int getLoginTimeout() {return 0;}
    @Override public @NonNull Logger getParentLogger() throws SQLFeatureNotSupportedException {throw new SQLFeatureNotSupportedException("No credential logging");}
    @Override public <@NonNull T> @NonNull T unwrap(@NonNull Class<@NonNull T> type) throws SQLException {throw new SQLFeatureNotSupportedException("No unwrap");}
    @Override public boolean isWrapperFor(@NonNull Class<?> type) {return false;}
}
