package me.aaronakhtar.wall;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import me.aaronakhtar.wall.configuration.AkhtarWallConfiguration;
import me.aaronakhtar.wall.threads.PacketHandler;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Enumeration;
import java.util.stream.Collectors;

public class AkhtarWall {
    private static final SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");

    public static final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    private static final double version = 4.0;
    protected static String NET_INTERFACE = "ens3";
    public static String publicIpv4 = "";
    public static boolean undrop = true;

    private static final File PPS_FILE = new File("/proc/net/dev");
    private static File TOTAL_INCOMING_BYTES_FILE = null;

    public static String PREFIX(){
        return "("+sdf.format(new Date())+")[AkhtarWall-"+version+"] ";
    }


    public static void main(String[] args) {
        System.out.println("Warning: AkhtarWall has only been tested on Debian-Based Distributions.");
        final File jsonConfigFile = new File(AkhtarWallConfiguration.configFilePath);
        if(!jsonConfigFile.exists()){
            System.out.println();
            System.out.println(AkhtarWall.PREFIX() + "Creating configuration file...");
            if (AkhtarWallConfiguration.createConfigFile()){
                System.out.println(AkhtarWall.PREFIX() + "Created configuration file ["+jsonConfigFile.getAbsolutePath()+"]...");
            }else{
                System.out.println(AkhtarWall.PREFIX() + "Failed creating configuration file...");
            }
            return;
        }

        try {

            final AkhtarWallConfiguration configuration = AkhtarWallConfiguration.get();

            if (configuration.isConfigInvalid()){
                System.out.println(AkhtarWall.PREFIX() + "Problems detected with your configuration...");
                return;
            }

            undrop = configuration.shouldRemoveDropsAfterMitigation();


            NET_INTERFACE = configuration.getNetworkInterface();
            MitigationOptions.maxConcurrentHandles = configuration.getMaxThreads();
            MitigationOptions.mitigationLengthInSeconds = configuration.getMitigationLengthInSeconds();
            MitigationOptions.ppsCap = configuration.getPpsTrigger();
            MitigationOptions.mbpsCap = configuration.getMbpsTrigger();
            PacketHandler.TOO_MANY_PACKETS = configuration.getMaxPacketsPerIp();
            PacketHandler.TOO_MANY_SPORT_ENTRIES = configuration.getMaxPacketsPerSourcePort();
            PacketHandler.TOO_MANY_SAME_PACKET_SIZES = configuration.getMaxSamePacketSizes();


            TOTAL_INCOMING_BYTES_FILE = new File(String.format("/sys/class/net/%s/statistics/rx_bytes", NET_INTERFACE));

            if (!PPS_FILE.exists() || !TOTAL_INCOMING_BYTES_FILE.exists()){
                System.out.println("Error: Cannot located required resources, please use a debian-based operating system...");
                return;
            }


            final Enumeration<InetAddress> inetAddressEnumeration = NetworkInterface.getByName(NET_INTERFACE).getInetAddresses();

            while(inetAddressEnumeration.hasMoreElements()){
                final InetAddress inetAddress = inetAddressEnumeration.nextElement();

                if(inetAddress instanceof Inet4Address && !inetAddress.isLoopbackAddress()){
                    publicIpv4 = inetAddress.getHostAddress();
                    break;
                }

            }

            MitigationOptions.blacklistedHosts.addAll(UtilFunctions.readFile(new File(configuration.getBlacklistedHostsFile())));
            MitigationOptions.blacklistedSourcePorts.addAll(UtilFunctions.readFile(new File(configuration.getBlacklistedSourcePortsFile())).stream().map(Integer::parseInt).collect(Collectors.toList()));




        }catch (Exception e){
            e.printStackTrace();
            return;
        }

        System.out.println();
        System.out.println(AkhtarWall.PREFIX() + "Settings:");
        System.out.println(AkhtarWall.PREFIX() + "  Public Ipv4 (interface="+ NET_INTERFACE +"): \""+publicIpv4+"\"");
        System.out.println(AkhtarWall.PREFIX() + "  Drop Ipv4 After: \""+ PacketHandler.TOO_MANY_PACKETS+" packets /per mitigation period\"");
        System.out.println(AkhtarWall.PREFIX() + "  Drop Source Port After: \""+ PacketHandler.TOO_MANY_SPORT_ENTRIES+" packets /per mitigation period\"");
        System.out.println(AkhtarWall.PREFIX() + "  Blacklisted Hosts: \""+MitigationOptions.blacklistedHosts.size()+"\"");
        System.out.println(AkhtarWall.PREFIX() + "  Blacklisted Source Ports: \""+MitigationOptions.blacklistedSourcePorts.size()+"\"");

        System.out.println();



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

                    PacketHandler.ips.clear();
                    PacketHandler.srcPorts.clear();


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
            final long current_total_bytes = Long.parseLong(Files.readAllLines(Paths.get(TOTAL_INCOMING_BYTES_FILE.toURI())).get(0));
            Thread.sleep(1000); // wait 1 second to get PER SECOND rate.
            final double current_mbps =
                    ((current_total_bytes - Long.parseLong(Files.readAllLines(Paths.get(TOTAL_INCOMING_BYTES_FILE.toURI())).get(0))) / 125000) * (-1);
            return current_mbps;
        }catch (Exception e) {}
        return 0;
    }

    private static String getTotalIncomingPackets(){
        try{
            try(BufferedReader reader = new BufferedReader(new FileReader(PPS_FILE))){
                String s;
                while((s = reader.readLine()) != null){
                    if (s.contains(NET_INTERFACE)){
                        return s.split(":")[1].split(" ")[2];
                    }
                }
            }
        }catch (Exception e){}
        return "ERR";
    }



}
