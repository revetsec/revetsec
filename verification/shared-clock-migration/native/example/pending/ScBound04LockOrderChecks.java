/*
 * Copyright 2026 Revetware LLC.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
package example.pending;

import org.jspecify.annotations.NonNull;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

/** Disposable PostgreSQL lock-order regression, using separate JVMs and forced lock-ID aliasing. */
public final class ScBound04LockOrderChecks {
    private static final long LOW=Long.MIN_VALUE+41, HIGH=Long.MAX_VALUE-17;
    private ScBound04LockOrderChecks() { }

    public static void run(Cap09ContentionChecks.@NonNull Harness harness)throws Exception {
        for(String family:List.of("TOTP","WEBAUTHN","ISSUER"))caseFor(harness,family);
    }
    private static void caseFor(Cap09ContentionChecks.@NonNull Harness harness,@NonNull String family)throws Exception {
        ExecutorService readers=Executors.newCachedThreadPool();
        Process a=null,b=null,c=null;
        try {
            String scope=harness.scope(family);
            a=worker(family,scope,"A");
            int aPid=ready(readers,a);
            check(family+"/merged-collision-uses-exclusive-signed-order",acquired(readers,a,aPid).equals("X:"+LOW+",X:"+HIGH));
            b=worker(family,scope,"B");
            int bPid=ready(readers,b);
            c=worker(family,scope,"C");
            int cPid=ready(readers,c);
            check(family+"/reversed-input-waits-on-first-sorted-lock",waitsFor(harness,bPid,aPid));
            check(family+"/shared-request-waits-on-merged-exclusive-mode",waitsFor(harness,cPid,aPid));
            release(a);
            check(family+"/reversed-input-completes-after-release",acquired(readers,b,bPid).equals("X:"+LOW+",X:"+HIGH));
            release(b);
            check(family+"/shared-request-completes-after-release",acquired(readers,c,cPid).equals("S:"+LOW));
            release(c);
            for(Process process:List.of(a,b,c))check(family+"/worker-exit-"+process.pid(),process.waitFor(3,TimeUnit.SECONDS)&&process.exitValue()==0);
        } finally {
            for(Process process:new Process[]{a,b,c})if(process!=null){process.destroyForcibly();process.waitFor(3,TimeUnit.SECONDS);}
            readers.shutdownNow();readers.awaitTermination(3,TimeUnit.SECONDS);
        }
    }
    private static @NonNull Process worker(@NonNull String family,@NonNull String scope,@NonNull String mode)throws Exception {
        return new ProcessBuilder(System.getProperty("java.home")+"/bin/java","-cp",System.getProperty("java.class.path"),ScBound04LockOrderChecks.class.getName(),family,scope,mode)
                .redirectErrorStream(true).start();
    }
    private static int ready(@NonNull ExecutorService readers,@NonNull Process process)throws Exception {
        String line=line(readers,process);
        if(!line.startsWith("READY "))throw new AssertionError("SC-BOUND-04 worker readiness: "+line);
        return Integer.parseInt(line.substring(6));
    }
    private static @NonNull String acquired(@NonNull ExecutorService readers,@NonNull Process process,int pid)throws Exception {
        String line=line(readers,process);
        String prefix="ACQUIRED "+pid+" ";
        if(!line.startsWith(prefix))throw new AssertionError("SC-BOUND-04 worker acquisition: "+line);
        return line.substring(prefix.length());
    }
    private static @NonNull String line(@NonNull ExecutorService readers,@NonNull Process process)throws Exception {
        Future<String> read=readers.submit(()->{StringBuilder result=new StringBuilder();int next;
            while((next=process.getInputStream().read())>=0&&next!='\n')result.append((char)next);
            return next<0&&result.length()==0?null:result.toString();});
        return Objects.requireNonNull(read.get(5,TimeUnit.SECONDS),"SC-BOUND-04 worker ended before protocol line");
    }
    private static void release(@NonNull Process process)throws Exception {process.getOutputStream().write(10);process.getOutputStream().flush();}
    private static boolean waitsFor(Cap09ContentionChecks.@NonNull Harness harness,int waiter,int holder)throws Exception {
        long end=System.nanoTime()+Duration.ofSeconds(3).toNanos();
        try(Connection connection=harness.open(Duration.ofSeconds(5));PreparedStatement statement=connection.prepareStatement(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=? AND wait_event_type='Lock' AND ?=ANY(pg_blocking_pids(pid)))")) {
            while(System.nanoTime()<end){statement.setInt(1,waiter);statement.setInt(2,holder);try(ResultSet result=statement.executeQuery()){result.next();if(result.getBoolean(1))return true;}LockSupport.parkNanos(1_000_000);}
        }
        return false;
    }
    private static void check(@NonNull String label,boolean passed){if(!passed)throw new AssertionError("SC-BOUND-04/"+label);System.out.println("PASS SC-BOUND-04/"+label);}

    public static void main(@NonNull String @NonNull [] args)throws Exception {
        if(args.length!=3)throw new IllegalArgumentException("Worker arguments");
        String family=args[0],scope=args[1],mode=args[2];
        try(Connection physical=DriverManager.getConnection(Objects.requireNonNull(System.getenv("DB_URL")),Objects.requireNonNull(System.getenv("DB_USER")),Objects.requireNonNull(System.getenv("DB_PASSWORD")))){
            physical.setAutoCommit(false);
            int pid;try(Statement statement=physical.createStatement();ResultSet result=statement.executeQuery("SELECT pg_backend_pid()")){result.next();pid=result.getInt(1);}
            System.out.println("READY "+pid);System.out.flush();
            List<String> trace=new ArrayList<>();Connection observed=observed(physical,trace);
            long deadline=System.nanoTime()+Duration.ofSeconds(12).toNanos();
            switch(family){
                case "TOTP" -> {TotpPgScope selected=TotpPgScope.from(family,scope);TotpPgLocks.sharedAdmission(observed,selected,deadline);TotpPgLocks.entities(observed,totp(mode),deadline);}
                case "WEBAUTHN" -> {WebAuthnPgScope selected=WebAuthnPgScope.from(family,scope);WebAuthnPgLocks.sharedAdmission(observed,selected,deadline);WebAuthnPgLocks.entities(observed,webauthn(mode),deadline);}
                case "ISSUER" -> {IssuerPgScope selected=IssuerPgScope.from(family,scope);IssuerPgLocks.sharedAdmission(observed,selected,deadline);IssuerPgLocks.entities(observed,issuer(mode),deadline);}
                default -> throw new IllegalArgumentException("Unknown family");
            }
            System.out.println("ACQUIRED "+pid+" "+String.join(",",trace));System.out.flush();
            if(System.in.read()<0)throw new IllegalStateException("Parent release missing");
            physical.commit();
        }
    }
    private static @NonNull List<TotpPgLocks.@NonNull Entity> totp(@NonNull String mode){return switch(mode){
        case "A"->List.of(TotpPgLocks.Entity.fromId(HIGH,true),TotpPgLocks.Entity.fromId(LOW,false),TotpPgLocks.Entity.fromId(LOW,true));
        case "B"->List.of(TotpPgLocks.Entity.fromId(LOW,true),TotpPgLocks.Entity.fromId(HIGH,true));
        case "C"->List.of(TotpPgLocks.Entity.fromId(LOW,false));default->throw new IllegalArgumentException("Mode");};}
    private static @NonNull List<WebAuthnPgLocks.@NonNull Entity> webauthn(@NonNull String mode){return switch(mode){
        case "A"->List.of(WebAuthnPgLocks.Entity.fromId(HIGH,true),WebAuthnPgLocks.Entity.fromId(LOW,false),WebAuthnPgLocks.Entity.fromId(LOW,true));
        case "B"->List.of(WebAuthnPgLocks.Entity.fromId(LOW,true),WebAuthnPgLocks.Entity.fromId(HIGH,true));
        case "C"->List.of(WebAuthnPgLocks.Entity.fromId(LOW,false));default->throw new IllegalArgumentException("Mode");};}
    private static @NonNull List<IssuerPgLocks.@NonNull Entity> issuer(@NonNull String mode){return switch(mode){
        case "A"->List.of(IssuerPgLocks.Entity.fromId(HIGH,true),IssuerPgLocks.Entity.fromId(LOW,false),IssuerPgLocks.Entity.fromId(LOW,true));
        case "B"->List.of(IssuerPgLocks.Entity.fromId(LOW,true),IssuerPgLocks.Entity.fromId(HIGH,true));
        case "C"->List.of(IssuerPgLocks.Entity.fromId(LOW,false));default->throw new IllegalArgumentException("Mode");};}
    private static @NonNull Connection observed(@NonNull Connection physical,@NonNull List<@NonNull String> trace){
        return (Connection)Proxy.newProxyInstance(Connection.class.getClassLoader(),new Class<?>[]{Connection.class},(proxy,method,args)->{
            try{
                Object value=method.invoke(physical,args);
                if(method.getName().equals("prepareStatement")&&args!=null&&args[0] instanceof String sql&&sql.startsWith("SELECT pg_advisory_xact_lock")&&sql.endsWith("(?)")&&value instanceof PreparedStatement statement){
                    final long[] id={0};
                    return Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(),new Class<?>[]{PreparedStatement.class},(p,m,a)->{
                        try{if(m.getName().equals("setLong")&&a!=null&&Integer.valueOf(1).equals(a[0]))id[0]=(Long)a[1];
                            if(m.getName().equals("execute"))trace.add((sql.contains("_shared")?"S:":"X:")+id[0]);
                            return m.invoke(statement,a);
                        }catch(InvocationTargetException wrapped){throw wrapped.getCause();}
                    });
                }
                return value;
            }catch(InvocationTargetException wrapped){throw wrapped.getCause();}
        });
    }
}
