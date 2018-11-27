package edu.trevecca.flare.collector;

import edu.trevecca.flare.core.logging.Logging;
import edu.trevecca.flare.core.redis.Redis;
import java.io.EOFException;
import java.net.Inet4Address;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.Builder;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import picocli.CommandLine;
import picocli.CommandLine.Option;

public class Main implements Callable<Void> {

    public static final Logger logger = Logging.getLogger("Main");
    private final Map<Inet4Address, AtomicInteger> outboundTraffic = new HashMap();
    private final Map<Inet4Address, AtomicInteger> inboundTraffic = new HashMap();
    private Instant start = Instant.now();
    @Option(
        names = {"-i", "--interface"}
    )
    private String interfaceName;
    @Option(
        names = {"-c", "--choose-interface"},
        description = {"Pick an interface from a list"},
        defaultValue = "false"
    )
    private boolean chooseInterface;
    @Option(
        names = {"-b", "--buffer-size"},
        description = {"The PCAP buffer size to use."},
        defaultValue = "2097152"
    )
    private int bufferSize;
    @Option(
        names = {"-f", "--filter"},
        description = {"The PCAP filter to use."},
        defaultValue = "tcp port 443 and ip proto \\tcp"
    )
    private String filter;
    @Option(
        names = {"-w", "--stats-window"},
        description = {"Time (in seconds) before a new stats dump is created."},
        defaultValue = "60"
    )
    private int statsWindow;
    private boolean doLoop = true;
    private PcapHandle handle;
    @Option(
        names = {"-rh", "--redis-host"},
        defaultValue = "localhost",
        description = {"Hostname of the redis server used for cross-node communication"}
    )
    private String redisHost;
    @Option(
        names = {"-rp", "--redis-port"},
        defaultValue = "6379",
        description = {"Port of the redis server used for cross-node communication"}
    )
    private int redisPort;
    public static Redis redis;

    public Main() {
    }

    public static void main(String[] args) throws Exception {
        CommandLine.call(new Main(), args);
    }

    public Void call() throws Exception {
        if (this.interfaceName == null && !this.chooseInterface) {
            logger.severe("Interface name not supplied and choose option disabled!");
            System.exit(1);
        }

        PcapNetworkInterface device = this.getNetworkDevice();
        if (device == null) {
            logger.severe("No device chosen!");
            System.exit(1);
        }

        logger.info("You chose: " + device.getName());
        Runtime.getRuntime().addShutdownHook(new Thread(this::finish));
        redis = Redis.builder(this.redisHost, this.redisPort).reconnect(true).build();
        redis.enable();
        int snapshotLength = 65536;
        int readTimeout = 50;
        Builder builder = new Builder(device.getName());
        builder.bufferSize(this.bufferSize).promiscuousMode(PromiscuousMode.PROMISCUOUS).timeoutMillis(readTimeout)
            .snaplen(snapshotLength);
        this.handle = builder.build();
        this.handle.setFilter(this.filter, BpfCompileMode.OPTIMIZE);

        while (this.doLoop) {
            if (Instant.now().minusSeconds((long) this.statsWindow).isAfter(this.start)) {
                Instant finalStart = this.start;
                (new Thread(() -> {
                    StatsUtils.dumpStats(finalStart, new HashMap(this.outboundTraffic), new HashMap(this.inboundTraffic),
                                         this.statsWindow, logger
                                        );
                })).run();
                this.outboundTraffic.clear();
                this.start = Instant.now();
            }

            try {
                Packet packet = this.handle.getNextPacketEx();
                if (packet.contains(IpV4Packet.class)) {
                    Inet4Address out = ((IpV4Packet) packet.get(IpV4Packet.class)).getHeader().getDstAddr();
                    Inet4Address in = ((IpV4Packet) packet.get(IpV4Packet.class)).getHeader().getSrcAddr();
                    byte[] outAddr = out.getAddress();
                    byte[] inAddr = in.getAddress();
                    if (!(outAddr[0] == (byte) 172 && outAddr[1] == (byte) 16)) {
                        this.outboundTraffic.putIfAbsent(out, new AtomicInteger());
                        ((AtomicInteger) this.outboundTraffic.get(out)).addAndGet(packet.getHeader().length());
                    }
                    else if (!(inAddr[0] == (byte) 172 && inAddr[1] == (byte) 16)) {
                        this.inboundTraffic.putIfAbsent(in, new AtomicInteger());
                        ((AtomicInteger) this.inboundTraffic.get(in)).addAndGet(packet.getHeader().length());
                    }
                    else {
                        logger.severe(
                            "UH OH! Looks like we got a packet not matching to/from 172.16: src " + in.getHostAddress() + "  dest"
                            + out.getHostAddress());
                    }

                }
            }
            catch (TimeoutException var7) {
                ;
            }
            catch (EOFException var8) {
                var8.printStackTrace();
            }
        }

        return null;
    }

    private void finish() {
        this.doLoop = false;

        try {
            logger.info("Shutting down...");
            Thread.sleep(400L);
            Logger shutdown = Logging.getLogger("Shutdown");
            PcapStat stats = this.handle.getStats();
            shutdown.info("Packets received: " + stats.getNumPacketsReceived());
            shutdown.info("Packets dropped: " + stats.getNumPacketsDropped());
            shutdown.info("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());
            StatsUtils.dumpStats(this.start, this.outboundTraffic, this.inboundTraffic, this.statsWindow, shutdown);
            this.handle.close();
        }
        catch (Exception var3) {
            var3.printStackTrace();
        }

    }

    private PcapNetworkInterface getNetworkDevice() {
        PcapNetworkInterface device = null;

        try {
            if (this.chooseInterface) {
                device = (new NifSelector()).selectNetworkInterface();
            }
            else {
                device = Pcaps.getDevByName(this.interfaceName);
            }
        }
        catch (Exception var3) {
            var3.printStackTrace();
        }

        return device;
    }
}