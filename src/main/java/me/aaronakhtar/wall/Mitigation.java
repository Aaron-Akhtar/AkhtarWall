package me.aaronakhtar.wall;

import me.aaronakhtar.wall.threads.IpHandler;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class Mitigation {

    public static final List<String> droppedHosts = new ArrayList<>();  // to prevent dupes.


    private static final String                         // 'NO_LOCAL_TRAFFIC_DUMP_FILTER' is something on the side im looking to implement - for now, not a priority.
            NO_LOCAL_TRAFFIC_DUMP_FILTER = "'not (src net (10 or 172.16/12 or 192.168/16) and dst net (10 or 172.16/12 or 192.168/16))'",
            DUMP_COMMAND = "tcpdump -i "+AkhtarWall.ETH_INTERFACE+" -n udp";

    public static final Runtime runtime = Runtime.getRuntime();
    public static volatile int runningHandles = 0;

    public static synchronized void mitigate(long endTime){
        while(!hasTimeEnded(endTime)){
            try {
                final Process dumpProcess = runtime.exec("timeout "+MitigationOptions.mitigationLengthInSeconds+" " + DUMP_COMMAND.trim());
               // System.out.println(DUMP_COMMAND);

                Thread.sleep(900);              // for the memes hehe

                try(BufferedReader reader = new BufferedReader(new InputStreamReader(dumpProcess.getInputStream()))){
                    String dumpLine;
                    while (!hasTimeEnded(endTime) && (dumpLine = reader.readLine()) != null) {
                        if (runningHandles >= MitigationOptions.maxConcurrentHandles) continue;
                        runningHandles++;
                        new Thread(new IpHandler(dumpLine)).start();
                        Thread.sleep(20);
                    }
                }

            }catch (Exception e){
                //e.printStackTrace();
            }
        }
    }


    private static boolean hasTimeEnded(long end){
        return System.currentTimeMillis() > end;
    }

}
