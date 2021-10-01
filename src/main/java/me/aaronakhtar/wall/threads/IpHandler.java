package me.aaronakhtar.wall.threads;

import me.aaronakhtar.wall.AkhtarWall;
import me.aaronakhtar.wall.Mitigation;
import me.aaronakhtar.wall.MitigationOptions;
import me.aaronakhtar.wall.UtilFunctions;

import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

public class IpHandler implements Runnable {

    public static int
            TOO_MANY_PACKETS = 0,
            TOO_MANY_SPORT_ENTRIES = 0; // during mitigation period only


    // will clear after every mitigation iteration
    public static final Map<String, Integer> ips = new HashMap<>();
    public static final Map<Integer, Integer> srcPorts = new HashMap<>();


    private String dumpLine;

    public IpHandler(String dumpLine) {
        this.dumpLine = dumpLine;
    }

    @Override
    public void run() {
        try{
            String ip;
            final String[] parts = dumpLine.split(" ");
            final String[] ipParts = parts[2].split("\\.");
            final StringJoiner stringJoiner = new StringJoiner(".");
            int sourcePort = 0;
            int xxF = 0;
            if (ipParts.length > 4) {
                for (String x : ipParts) {
                    xxF++;
                    if (xxF == 5){
                        sourcePort = Integer.parseInt(x);
                    }else {
                        stringJoiner.add(x);
                    }
                }

                ip = stringJoiner.toString();

            }else{
                ip = parts[2];
            }

            final String
                    IN_IP_ADDRESS = ip;

            if (IN_IP_ADDRESS.equals(AkhtarWall.publicIpv4)){
                Mitigation.runningHandles--;
                return;
            }

            if (MitigationOptions.blacklistedHosts.contains(IN_IP_ADDRESS)){
                Mitigation.runningHandles--;
                return;
            }

            final int
                    IP_PART_1 = Integer.parseInt(ipParts[0]),
                    IP_PART_2 = Integer.parseInt(ipParts[1]);


            if (Mitigation.droppedHosts.contains(IN_IP_ADDRESS) || IP_PART_1 == 10 || (IP_PART_1 == 172 && (IP_PART_2 >= 16 && IP_PART_2 <= 31)) || (IP_PART_1 == 192 && IP_PART_2 == 168)){
                Mitigation.runningHandles--;
                return;
            }


            if (ips.get(IN_IP_ADDRESS) == null){
                ips.put(IN_IP_ADDRESS, 0);
            }else{
                ips.put(IN_IP_ADDRESS, ips.get(IN_IP_ADDRESS) + 1);
            }

            if (srcPorts.get(sourcePort) == null){
                srcPorts.put(sourcePort, 0);
            }else{
                srcPorts.put(sourcePort, srcPorts.get(sourcePort) + 1);
            }

            final int
                    totalRecPacketsFromHost = ips.get(IN_IP_ADDRESS),
                    totalSrcPortEntries = srcPorts.get(sourcePort);

            if (totalSrcPortEntries >= TOO_MANY_SPORT_ENTRIES){
                UtilFunctions.dropSourcePort(sourcePort);
                Mitigation.runningHandles--;
                return;
            }

            if (totalRecPacketsFromHost >= TOO_MANY_PACKETS){
                UtilFunctions.dropIp(IN_IP_ADDRESS);
                Mitigation.runningHandles--;
                return;
            }


                        // just assuming bad lengths are malicious during mitigation.
            if (dumpLine.contains("bad length")){
                UtilFunctions.dropIp(IN_IP_ADDRESS);
                Mitigation.runningHandles--;
                return;
            }




        }catch (Exception e){

        }

        Mitigation.runningHandles--;
    }




}
