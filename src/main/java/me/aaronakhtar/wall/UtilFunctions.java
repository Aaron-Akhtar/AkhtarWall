package me.aaronakhtar.wall;

import me.aaronakhtar.wall.threads.PacketHandler;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class UtilFunctions {

    private static final int MAX_CONCURRENT_EXECUTIONS =
            MitigationOptions.maxConcurrentHandles / 2;
    private static volatile int CURRENT_CONCURRENT_EXECUTIONS = 0;

    public static List<String> readFile(File file){
        final List<String> content = new ArrayList<>();
        try(BufferedReader reader = new BufferedReader(new FileReader(file))){
            String s;
            while((s = reader.readLine()) != null){
                content.add(s);
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return content;
    }


    private static final SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy-HH-mm-ss");

    public enum LogType{
        IP, SPORT, PSIZE;
    }

    public static PrintWriter getLogNewLogStream(LogType logType){
        File logFile = null; //new File(((logType == LogType.IP) ? MitigationOptions.LOG_DIRECTORY() + "/" + sdf.format(new Date()) + ".txt" : MitigationOptions.MAIN_DIRECTORY + "/droppedSourcePorts.txt"));

        switch (logType){
            case IP:{
                logFile = new File(MitigationOptions.LOG_DIRECTORY() + "/droppedHosts-" + sdf.format(new Date()) + ".txt");
                break;
            }

            case PSIZE:{
                logFile = new File(MitigationOptions.LOG_DIRECTORY() + "/droppedPacketSizes-"+ sdf.format(new Date())+".txt");
                break;
            }

            case SPORT:{
                logFile = new File(MitigationOptions.LOG_DIRECTORY() + "/droppedSourcePorts-" + sdf.format(new Date()) + ".txt");
                break;
            }
        }

        try {
            if (!logFile.exists()) logFile.createNewFile();
            return new PrintWriter(new FileWriter(logFile, true), true);
        }catch (Exception e){

        }
        return null;
    }

    public static void dropPacketSize(int psize, boolean undrop){
        if (!undrop && Mitigation.droppedPacketSizes.contains(psize)) return;
        while(CURRENT_CONCURRENT_EXECUTIONS >= MAX_CONCURRENT_EXECUTIONS);
        CURRENT_CONCURRENT_EXECUTIONS++;
        try{
            Mitigation.runtime.exec("iptables -t raw "+((undrop) ? "-D" : "-A")+" PREROUTING -p udp -m length --length "+psize+" -j DROP");

            if (undrop){
                System.out.println(AkhtarWall.PREFIX() + "Un-dropped Potentially Malicious Packet Size: [entries=" + PacketHandler.packetSizes.get(psize) + " | psize=" + psize + "]");
            }else {
                System.out.println(AkhtarWall.PREFIX() + "Dropped Potentially Malicious Packet Size: [entries=" + PacketHandler.packetSizes.get(psize) + " | psize=" + psize + "]");
                Mitigation.droppedPacketSizes.add(psize);
                Mitigation.psizeLogWriter.println(psize);
            }
        }catch (Exception e){

        }
        CURRENT_CONCURRENT_EXECUTIONS--;
    }

    public static void dropSourcePort(int sport, boolean undrop){
        if (!undrop && Mitigation.droppedSourcePorts.contains(sport)) return;
        while(CURRENT_CONCURRENT_EXECUTIONS >= MAX_CONCURRENT_EXECUTIONS);
        CURRENT_CONCURRENT_EXECUTIONS++;
        try{
            Mitigation.runtime.exec("iptables -t raw "+((undrop) ? "-D" : "-A")+" PREROUTING -p udp  --sport "+sport+" -j DROP");

            if (undrop){
                System.out.println(AkhtarWall.PREFIX() + "Un-dropped Potentially Malicious Source Port: [entries=" + PacketHandler.srcPorts.get(sport) + " | sport=" + sport + "]");
            }else {
                System.out.println(AkhtarWall.PREFIX() + "Dropped Potentially Malicious Source Port: [entries=" + PacketHandler.srcPorts.get(sport) + " | sport=" + sport + "]");
                Mitigation.droppedSourcePorts.add(sport);
                Mitigation.sportLogWriter.println(sport);
            }
        }catch (Exception e){

        }
        CURRENT_CONCURRENT_EXECUTIONS--;
    }

    public static void dropIp(String ip, boolean undrop) {
        if (!undrop && Mitigation.droppedHosts.contains(ip)) return;
        while(CURRENT_CONCURRENT_EXECUTIONS >= MAX_CONCURRENT_EXECUTIONS);
        CURRENT_CONCURRENT_EXECUTIONS++;
        try {
            Mitigation.runtime.exec("iptables -t raw "+((undrop) ? "-D" : "-A")+" PREROUTING -s " + ip + " -j DROP");

            if (undrop){
                System.out.println(AkhtarWall.PREFIX() + "Un-dropped Potentially Malicious Host: [entries="+ PacketHandler.ips.get(ip) +" | host=" + ip + "]");
            }else{
                System.out.println(AkhtarWall.PREFIX() + "Dropped Potentially Malicious Host: [entries="+ PacketHandler.ips.get(ip) +" | host=" + ip + "]");
                Mitigation.droppedHosts.add(ip);
                Mitigation.ipLogWriter.println(ip);
            }
        }catch (Exception e){

        }
        CURRENT_CONCURRENT_EXECUTIONS--;
    }

}
