package me.aaronakhtar.wall.configuration;

import me.aaronakhtar.wall.AkhtarWall;
import me.aaronakhtar.wall.MitigationOptions;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;

public class AkhtarWallConfiguration {
    public static final String configFilePath = MitigationOptions.MAIN_DIRECTORY + "/config.json";

    public static final AkhtarWallConfiguration get() throws Exception{
        try(FileReader fileReader = new FileReader(configFilePath)){
            return AkhtarWall.gson.fromJson(fileReader, AkhtarWallConfiguration.class);
        }
    }

    public static final boolean createConfigFile(){
        try {
            final File config = new File(configFilePath);
            final File parent = config.getParentFile();
            if (!parent.isDirectory()) parent.mkdirs();
            // assuming user checked the files existence before executing.
            if (config.createNewFile()) {
                try(FileWriter fileWriter = new FileWriter(config)) {
                    AkhtarWall.gson.toJson(new AkhtarWallConfiguration(), fileWriter);
                    fileWriter.flush();
                }
                return true;
            }
        }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }

    private String  networkInterface = "";
    private int     maxThreads = 1000;
    private int     mitigationLengthInSeconds = 60;
    private long    ppsTrigger = 0;
    private double  mbpsTrigger = 50;
    private int     maxPacketsPerIp = 250;
    private int     maxPacketsPerSourcePort = 200;
    private int     maxSamePacketSizes = 250;
    private String  blacklistedSourcePortsFile = "";
    private String  blacklistedHostsFile = "";
    private boolean removeDropsAfterMitigation = true;

    public boolean isConfigInvalid(){
        return networkInterface.isEmpty() || blacklistedHostsFile.isEmpty() || maxThreads == 0;
    }

    public String getNetworkInterface() {
        return networkInterface;
    }

    public int getMaxThreads() {
        return maxThreads;
    }

    public int getMitigationLengthInSeconds() {
        return mitigationLengthInSeconds;
    }

    public long getPpsTrigger() {
        return ppsTrigger;
    }

    public double getMbpsTrigger() {
        return mbpsTrigger;
    }

    public int getMaxPacketsPerIp() {
        return maxPacketsPerIp;
    }

    public int getMaxPacketsPerSourcePort() {
        return maxPacketsPerSourcePort;
    }

    public int getMaxSamePacketSizes() {
        return maxSamePacketSizes;
    }

    public String getBlacklistedSourcePortsFile() {
        return blacklistedSourcePortsFile;
    }

    public String getBlacklistedHostsFile() {
        return blacklistedHostsFile;
    }

    public boolean shouldRemoveDropsAfterMitigation() {
        return removeDropsAfterMitigation;
    }
}
