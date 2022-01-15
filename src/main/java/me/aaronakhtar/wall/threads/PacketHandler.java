package me.aaronakhtar.wall.threads;

import me.aaronakhtar.wall.AkhtarWall;
import me.aaronakhtar.wall.Mitigation;
import me.aaronakhtar.wall.MitigationOptions;
import me.aaronakhtar.wall.UtilFunctions;

import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

public class PacketHandler implements Runnable {

    public static int
            TOO_MANY_PACKETS = 0,
            TOO_MANY_SPORT_ENTRIES = 0, // during mitigation period only
            TOO_MANY_SAME_PACKET_SIZES = 0;

    // will clear after every mitigation iteration
    public static final Map<String, Integer> ips = new HashMap<>();
    public static final Map<Integer, Integer>
            srcPorts = new HashMap<>(),
            packetSizes = new HashMap<>();


    private String dumpLine;

    public PacketHandler(String dumpLine) {
        this.dumpLine = dumpLine;
    }

    @Override
    public void run() {
        try {
            boolean isSourcePortBlacklisted = false;
            boolean skipPacketSize = false;
            String ip;
            final String[] parts = dumpLine.split(" ");
            final String[]
                    ipParts = parts[2].split("\\.");

            final int
                    IP_PART_1 = Integer.parseInt(ipParts[0]),
                    IP_PART_2 = Integer.parseInt(ipParts[1]);
            final StringJoiner stringJoiner = new StringJoiner(".");
            int sourcePort = 0;
            int xxF = 0;
            if (ipParts.length > 4) {
                for (String x : ipParts) {
                    xxF++;
                    if (xxF == 5) {
                        sourcePort = Integer.parseInt(x);
                    } else {
                        stringJoiner.add(x);
                    }
                }

                ip = stringJoiner.toString();

            } else {
                ip = parts[2];
            }

            final String
                    IN_IP_ADDRESS = ip;

            if (IN_IP_ADDRESS.equals(AkhtarWall.publicIpv4)) {
                return;
            }

            if (MitigationOptions.blacklistedHosts.contains(IN_IP_ADDRESS)) {
                return;
            }


            if (Mitigation.droppedHosts.contains(IN_IP_ADDRESS) || IP_PART_1 == 10 || (IP_PART_1 == 172 && (IP_PART_2 >= 16 && IP_PART_2 <= 31)) || (IP_PART_1 == 192 && IP_PART_2 == 168)) {
                return;
            }

            if (dumpLine.contains("bad length")) {
                skipPacketSize = true;
                UtilFunctions.dropIp(IN_IP_ADDRESS, false);
            }

            final String packetSizePart = (skipPacketSize) ? "" : parts[parts.length - 1];
            int packetSize = 0;

            if (!skipPacketSize) {
                try {
                    packetSize = Integer.parseInt(packetSizePart);
                } catch (NumberFormatException ex) {
                    //    ex.printStackTrace();
                    skipPacketSize = true;
                }
            }

            //  System.out.println("Same Sizes ("+packetSize+") ("+isBadLength+") : " + packetSizes.get(packetSize));
            if (MitigationOptions.blacklistedSourcePorts.contains(sourcePort)) isSourcePortBlacklisted = true;

            if (!AkhtarWall.configuration.isShouldDisableHostDropping()) {
                if (ips.get(IN_IP_ADDRESS) == null) {
                    ips.put(IN_IP_ADDRESS, 0);
                } else {
                    ips.put(IN_IP_ADDRESS, ips.get(IN_IP_ADDRESS) + 1);
                }
            }

            if (!!AkhtarWall.configuration.isShouldDisableSourcePortDropping() && !isSourcePortBlacklisted) {
                if (srcPorts.get(sourcePort) == null) {
                    srcPorts.put(sourcePort, 0);
                } else {
                    srcPorts.put(sourcePort, srcPorts.get(sourcePort) + 1);
                }
            }

            if (!skipPacketSize) {
                if (packetSizes.get(packetSize) == null) {
                    packetSizes.put(packetSize, 0);
                } else {
                    packetSizes.put(packetSize, packetSizes.get(packetSize) + 1);
                }
            }

            final int
                    totalReceivedPacketsFromHost = ips.get(IN_IP_ADDRESS),
                    totalSrcPortEntries = srcPorts.get(sourcePort),
                    totalPacketSizeEntries = (skipPacketSize) ? 0 : packetSizes.get(packetSize);


            // no longer returning after these checks, so if multiple values are true, it can execute multiple rules in one handle.

            if (!isSourcePortBlacklisted && totalSrcPortEntries >= TOO_MANY_SPORT_ENTRIES){
                UtilFunctions.dropSourcePort(sourcePort, false);
              //  return;
            }

            if (totalReceivedPacketsFromHost >= TOO_MANY_PACKETS){
                UtilFunctions.dropIp(IN_IP_ADDRESS, false);
                //return;
            }

            if (!skipPacketSize && !AkhtarWall.configuration.isShouldDisablePacketSizeDropping()) {
                if (totalPacketSizeEntries >= TOO_MANY_SAME_PACKET_SIZES) {
                    UtilFunctions.dropPacketSize(packetSize, false);
                }
            }




        }catch (Exception e){
         //   e.printStackTrace();
        }finally {
            Mitigation.runningHandles--;
        }
    }




}
