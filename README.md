Support Discord: http://akhtarwall-discord.aaronakhtar.me

# AkhtarWall
AkhtarWall provides Layer-4 DDOS Mitigation (UDP only (for now)), at the Software Level, utilizing the following software:

- (REQUIRED DEPENDENCY) TCPDUMP -> in order to read incoming traffic from target network interface.
- (REQUIRED DEPENDENCY) IPTABLES -> in order to drop deemed malicious traffic.

(Download: https://github.com/Aaron-Akhtar/AkhtarWall/releases/download/3.0/AkhtarWall.jar)

During the mitigation period, it will LIVE/CONCURRENTLY transmit logs to a unique file in the directory: 
```
./AkhtarWall/logs/%dd-MM-yyyy-HH-mm-ss%.txt
./AkhtarWall/droppedSourcePorts.txt
```

### How to use AkhtarWall on Debian >
```shell
# Download AkhtarWall Executable Jar
wget https://github.com/Aaron-Akhtar/AkhtarWall/releases/download/3.0/AkhtarWall.jar

# To start, install the JRE (Java)
apt-get install default-jre -y

# Next, install TCPDUMP, one of the required dependencies
apt-get install tcpdump -y

# Last, but not least, install IPTABLES
apt-get install iptables -y
```

In order to start running AkhtarWall, execute the following command:
```
java -jar AkhtarWall.jar [NET_INTERFACE] [MAX_THREADS] [MITIGATION_LENGTH_SECONDS] [PPS_TRIGGER] [MBPS_TRIGGER] [MAX_PACKETS_PER_IP] [BLACKLISTED_HOSTS_FILE]
```
Example Command:
```
java -jar AkhtarWall.jar eth0 45 60 2000 10 3 blacklisted-ips.txt
```

*Developed by Yours Truly, Aaron Akhtar...*
