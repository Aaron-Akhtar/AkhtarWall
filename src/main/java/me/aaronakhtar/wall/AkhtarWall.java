package me.aaronakhtar.wall;

import me.aaronakhtar.wall.threads.IpHandler;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;

public class AkhtarWall {
    private static final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");

    private static final double version = 2.0;
    public static String ETH_INTERFACE = "ens3";

    private static final String
            PPS_FILE = "/proc/net/dev",
            TOTAL_INCOMING_BYTES_FILE = "/sys/class/net/%s/statistics/rx_bytes";



    public static String PREFIX(){
        return "("+sdf.format(new Date())+")[AkhtarWall-"+version+"] ";
    }


    public static void main(String[] args) {

        if(args.length != 6){
            System.out.println("Warning: AkhtarWall has only been tested on Debian-Based Distributions.");
            System.out.println();
            System.out.println(AkhtarWall.PREFIX() + "Correct Args: 'java -jar AkhtarWall.jar [NET_INTERFACE] [MAX_THREADS] [MITIGATION_LENGTH_SECONDS] [PPS_TRIGGER] [MBPS_TRIGGER] [MAX_PACKETS_PER_IP]'");

            return;
        }

        ETH_INTERFACE = args[0];
        MitigationOptions.maxConcurrentHandles = Integer.parseInt(args[1]);
        MitigationOptions.mitigationLengthInSeconds = Integer.parseInt(args[2]);
        MitigationOptions.ppsCap = Long.parseLong(args[3]);
        MitigationOptions.mbpsCap = Double.parseDouble(args[4]);
        IpHandler.TOO_MANY_PACKETS = Integer.parseInt(args[5]);






        int mitigatedAttacks = 0;

        while(true){
            try {
                final long pps = getCurrentIncomingPps();
                final double mbps = getCurrentIncomingMbps();

                if (pps >= MitigationOptions.ppsCap && mbps >= MitigationOptions.mbpsCap) {

                    mitigatedAttacks++;

                    System.out.println(AkhtarWall.PREFIX() + "{ATTACK_ID="+mitigatedAttacks+"} (D)DOS Attack Detected: ["+mbps+"MBps] ["+pps+"pps]");

                    final long mitigationEnd = System.currentTimeMillis() + (MitigationOptions.mitigationLengthInSeconds * 1000);

                    System.out.println(AkhtarWall.PREFIX() + "{ATTACK_ID="+mitigatedAttacks+"} (D)DOS Mitigation Started For "+MitigationOptions.mitigationLengthInSeconds+"s!");

                    Mitigation.mitigate(mitigationEnd);

                    IpHandler.ips.clear();


                    System.out.println(AkhtarWall.PREFIX() + "{ATTACK_ID="+mitigatedAttacks+"} (D)DOS Mitigation Ended: [totalDropped="+Mitigation.droppedHosts.size()+"]");

                }
                Thread.sleep(120);
            }catch (Exception e){
                e.printStackTrace();
            }
        }



    }


    private static long getCurrentIncomingPps(){
        try {
            final long pps1 = Long.parseLong(getTotalIncomingPackets());
            Thread.sleep(1000); // wait 1 second to get PER SECOND rate.
            return Long.parseLong(getTotalIncomingPackets()) - pps1;
        }catch (Exception e){}
        return 0;
    }

    private static double getCurrentIncomingMbps(){
        try{
            final long current_total_bytes = Long.parseLong(Files.readAllLines(Paths.get(new File(String.format(TOTAL_INCOMING_BYTES_FILE, ETH_INTERFACE)).toURI())).get(0));
            Thread.sleep(1000); // wait 1 second to get PER SECOND rate.
            final double current_mbps =
                    ((current_total_bytes - Long.parseLong(Files.readAllLines(Paths.get(new File(String.format(TOTAL_INCOMING_BYTES_FILE, ETH_INTERFACE)).toURI())).get(0))) / 125000) * (-1);
            return current_mbps;
        }catch (Exception e) {}
        return 0;
    }

    private static String getTotalIncomingPackets(){
        try{
            try(BufferedReader reader = new BufferedReader(new FileReader(PPS_FILE))){
                String s;
                while((s = reader.readLine()) != null){
                    if (s.contains(ETH_INTERFACE)){
                        return s.split(":")[1].split(" ")[2];
                    }
                }
            }
        }catch (Exception e){}
        return "ERR";
    }



}
