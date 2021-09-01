package me.aaronakhtar.wall.threads;

import me.aaronakhtar.wall.Mitigation;
import me.aaronakhtar.wall.UtilFunctions;

import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

public class IpHandler implements Runnable {

    private static final int TOO_MANY_PACKETS = 10; // during mitigation period only

    public static final Map<String, Integer> ips = new HashMap<>();     // will clear after mitigation

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
            int xxF = 0;
            if (ipParts.length > 4) {
                for (String x : ipParts) {
                    xxF++;
                    stringJoiner.add(x);
                    if (xxF == 4) break;
                }

                ip = stringJoiner.toString();

            }else{
                ip = parts[2];
            }

            final String
                    IN_IP_ADDRESS = ip;


            if (Mitigation.droppedHosts.contains(IN_IP_ADDRESS)){
                Mitigation.runningHandles--;
                return;
            }


            if (ips.get(IN_IP_ADDRESS) == null){
                ips.put(IN_IP_ADDRESS, 0);
            }else{
                final int x = ips.get(IN_IP_ADDRESS) + 1;
                ips.put(IN_IP_ADDRESS, x);
                if (x >= TOO_MANY_PACKETS){
                    UtilFunctions.dropIp(IN_IP_ADDRESS);
                    Mitigation.runningHandles--;
                    return;
                }
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
