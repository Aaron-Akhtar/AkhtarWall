package me.aaronakhtar.wall;

import me.aaronakhtar.wall.threads.IpHandler;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

public class UtilFunctions {

    public static void main(String[] args) {
        System.out.println(30 * (100 / 10));
    }

    private static final int MAX_CONCURRENT_EXECUTIONS =
            MitigationOptions.maxConcurrentHandles / 2;
    private static volatile int CURRENT_CONCURRENT_EXECUTIONS = 0;

    private static final SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy-HH-mm-ss");

    public enum LogType{
        IP, SPORT;
    }

    public static PrintWriter getLogNewLogStream(LogType logType){
        final File logFile = new File(((logType == LogType.IP) ? MitigationOptions.LOG_DIRECTORY() + "/" + sdf.format(new Date()) + ".txt" : MitigationOptions.MAIN_DIRECTORY + "/droppedSourcePorts.txt"));
        try {
            if (!logFile.exists()) logFile.createNewFile();
            return new PrintWriter(new FileWriter(logFile, true), true);
        }catch (Exception e){

        }
        return null;
    }

    public static void dropSourcePort(int sport){
        if (Mitigation.droppedSourcePorts.contains(sport)) return;
        while(CURRENT_CONCURRENT_EXECUTIONS >= MAX_CONCURRENT_EXECUTIONS);
        CURRENT_CONCURRENT_EXECUTIONS++;
        try{
            Mitigation.runtime.exec("iptables -t raw -A PREROUTING -p udp  --sport "+sport+" -j DROP");
            System.out.println(AkhtarWall.PREFIX() + "Dropped Potentially Malicious Source Port: [entries="+ IpHandler.srcPorts.get(sport) +" | sport=" + sport + "]");
            Mitigation.droppedSourcePorts.add(sport);
            Mitigation.sportLogWriter.println(sport);
        }catch (Exception e){

        }
        CURRENT_CONCURRENT_EXECUTIONS--;
    }

    public static void dropIp(String ip) {
        if (Mitigation.droppedHosts.contains(ip)) return;
        while(CURRENT_CONCURRENT_EXECUTIONS >= MAX_CONCURRENT_EXECUTIONS);
        CURRENT_CONCURRENT_EXECUTIONS++;
        try {
            Mitigation.runtime.exec("iptables -t raw -A PREROUTING -s " + ip + " -j DROP");
            System.out.println(AkhtarWall.PREFIX() + "Dropped Potentially Malicious Host: [entries="+ IpHandler.ips.get(ip) +" | host=" + ip + "]");
            Mitigation.droppedHosts.add(ip);
            Mitigation.ipLogWriter.println(ip);
        }catch (Exception e){

        }
        CURRENT_CONCURRENT_EXECUTIONS--;
    }

}
