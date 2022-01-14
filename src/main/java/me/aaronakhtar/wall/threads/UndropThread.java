package me.aaronakhtar.wall.threads;

import me.aaronakhtar.wall.Mitigation;
import me.aaronakhtar.wall.UtilFunctions;

public class UndropThread implements Runnable {

    private final Object target;
    private final UtilFunctions.LogType type;

    public UndropThread(Object target, UtilFunctions.LogType type) {
        this.target = target;
        this.type = type;
    }

    @Override
    public void run() {
        try {
            switch (type){
                case PSIZE:{
                    UtilFunctions.dropPacketSize((int)target, true);
                    break;
                }
                case IP:{
                    UtilFunctions.dropIp(target.toString(), true);
                    break;
                }
                case SPORT:{
                    UtilFunctions.dropSourcePort((int)target, true);
                    break;
                }
            }
            Mitigation.runningHandles--;
        }catch (Exception e){
            // todo write excption handler
        }
    }
}
