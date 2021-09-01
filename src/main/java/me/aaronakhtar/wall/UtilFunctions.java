package me.aaronakhtar.wall;

public class UtilFunctions {

    public static void dropIp(String ip) throws Exception {
        if (Mitigation.droppedHosts.contains(ip)) return;
        Mitigation.runtime.exec("iptables -I INPUT -s "+ip+" -j DROP");
        Mitigation.droppedHosts.add(ip);
        System.out.println(AkhtarWall.PREFIX + "Dropped Potentially Malicious Host: [" + ip + "]");
    }

}
