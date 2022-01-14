package me.aaronakhtar.wall;

import me.aaronakhtar.wall.threads.PacketHandler;
import me.aaronakhtar.wall.threads.UndropThread;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("Duplicates")
public class Mitigation {

    public static final List<String> droppedHosts = new ArrayList<>();  // to prevent dupes.
    public static final List<Integer>
            droppedSourcePorts = new ArrayList<>(),
            droppedPacketSizes = new ArrayList<>();


    private static final String DUMP_COMMAND = "tcpdump -i "+AkhtarWall.NET_INTERFACE +" -n udp";

    public static final Runtime runtime = Runtime.getRuntime();
    public static volatile int runningHandles = 0;

    public static PrintWriter
            ipLogWriter = null,
            sportLogWriter = null,
            psizeLogWriter = null;

    public static synchronized void mitigate(long endTime){
        ipLogWriter = UtilFunctions.getLogNewLogStream(UtilFunctions.LogType.IP);
        sportLogWriter = UtilFunctions.getLogNewLogStream(UtilFunctions.LogType.SPORT);
        psizeLogWriter = UtilFunctions.getLogNewLogStream(UtilFunctions.LogType.PSIZE);
        if (ipLogWriter == null || sportLogWriter == null   ){
            System.out.println(AkhtarWall.PREFIX() + "! Fatal Error !  - unable to create log file stream...");
            return;
        }
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
                        new Thread(new PacketHandler(dumpLine)).start();
                        Thread.sleep(25);
                    }
                }

            }catch (Exception e){
                //e.printStackTrace();
            }
        }
        //ended

        System.out.println();

        System.out.println(AkhtarWall.PREFIX() + "Un-dropping all hosts & source ports now that mitigation is over...");
        System.out.println(AkhtarWall.PREFIX() + "Network may be vulnerable to (D)DOS attacks during this period...");

        System.out.println();

        if (runningHandles > 0) {
            System.out.println(AkhtarWall.PREFIX() + "Waiting for ["+runningHandles+"] packet handlers to finish...");
            while(runningHandles > 0);
            System.out.println(AkhtarWall.PREFIX() + "Packet handlers have finished...");
        }

        if (AkhtarWall.undrop) {
            final List<String> undroppedHosts = new ArrayList<>();
            final List<Integer>
                    undroppedSourcePorts = new ArrayList<>(),
                    undroppedPacketSizes = new ArrayList<>();
            try {
                for (String host : droppedHosts) {
                    while (runningHandles >= MitigationOptions.maxConcurrentHandles) ;
                    runningHandles++;
                    new Thread(new UndropThread(host, UtilFunctions.LogType.IP)).start();
                    undroppedHosts.add(host);
                    Thread.sleep(25);
                }
                while (runningHandles != 0) ;
                droppedHosts.removeAll(undroppedHosts);

                for (int port : droppedSourcePorts) {
                    while (runningHandles >= MitigationOptions.maxConcurrentHandles) ;
                    runningHandles++;
                    new Thread(new UndropThread(port, UtilFunctions.LogType.SPORT)).start();
                    undroppedSourcePorts.add(port);
                    Thread.sleep(25);
                }
                while (runningHandles != 0) ;
                droppedSourcePorts.removeAll(undroppedSourcePorts);

                for (int size : droppedPacketSizes) {
                    while (runningHandles >= MitigationOptions.maxConcurrentHandles) ;
                    runningHandles++;
                    new Thread(new UndropThread(size, UtilFunctions.LogType.PSIZE)).start();
                    undroppedPacketSizes.add(size);
                    Thread.sleep(25);
                }
                while (runningHandles != 0) ;
                droppedPacketSizes.removeAll(undroppedPacketSizes);
            }catch (InterruptedException e){

            }
        }

    }


    private static boolean hasTimeEnded(long end){
        return System.currentTimeMillis() > end;
    }

}
