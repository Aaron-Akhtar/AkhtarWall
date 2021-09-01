# AkhtarWall
AkhtarWall provides Layer-4 DDOS Mitigation (UDP only (for now)), at the Software Level, utilizing the following software:

 - (REQUIRED DEPENDENCY) TCPDUMP -> in order to read incoming traffic from target network interface.
 - (REQUIRED DEPENDENCY) IPTABLES -> in order to drop deemed malicious traffic. 

(Download: https://github.com/Aaron-Akhtar/AkhtarWall/releases/download/1.0/AkhtarWall.jar)

### How to use AkhtarWall on Debian >
```shell
# To start, install the JRE (Java)
apt-get install default-jre -y

# Next, install TCPDUMP, one of the required dependencies
apt-get install tcpdump -y

# Last, but not least, install IPTABLES
apt-get install iptables -y
```

In order to start running AkhtarWall, execute the following command:
```
java -jar AkhtarWall.jar [interface] [max_threads]
```
Example Command:
```
java -jar AkhtarWall.jar eth0 150
```

*Developed by Yours Truly, Aaron Akhtar...*
