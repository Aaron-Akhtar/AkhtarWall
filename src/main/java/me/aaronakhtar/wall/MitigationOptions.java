package me.aaronakhtar.wall;

public class MitigationOptions {

    public static final long    ppsCap = 5000;    // pps to be reached for mitigation
    public static final double  mbpsCap = 5;      // mbps to be reached for mitigation
    public static int
            maxConcurrentHandles = 100, //default 100
            mitigationLengthInSeconds = 300;

}
