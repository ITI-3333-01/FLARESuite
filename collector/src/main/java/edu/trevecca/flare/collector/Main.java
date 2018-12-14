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
import java.util.function.Predicate;
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

    /**
     * Check to see if local data should be discarded.
     */
    private static final Predicate<byte[]> DISCARD_CHECK = (addr) -> (addr[0] == (byte) 172 && addr[1] == (byte) 16);
    /**
     * Class logger
     */
    private static final Logger logger = Logging.getLogger("Main");
    /**
     * Traffic which is heading out of the network.
     */
    private final Map<Inet4Address, AtomicInteger> outboundTraffic = new HashMap();
    /**
     * Traffic which is heading in to the network.
     */
    private final Map<Inet4Address, AtomicInteger> inboundTraffic = new HashMap();
    /**
     * Time when the current stats window started.
     */
    private Instant start = Instant.now();
    /**
     * Name of the interface to sniff packets from.
     */
    @Option(
        names = {"-i", "--interface"}
    )
    private String interfaceName;
    /**
     * If an interface should be picked from a list, rather than by name. This and {@link #interfaceName} cannot both be provided
     * at the same time, but one or the other most be provided for an interface to be chosen.
     */
    @Option(
        names = {"-c", "--choose-interface"},
        description = {"Pick an interface from a list"},
        defaultValue = "false"
    )
    private boolean chooseInterface;
    /**
     * The PCAP buffer size to use.
     */
    @Option(
        names = {"-b", "--buffer-size"},
        description = {"The PCAP buffer size to use."},
        defaultValue = "2097152"
    )
    private int bufferSize;
    /**
     * The PCAP filter to use.
     */
    @Option(
        names = {"-f", "--filter"},
        description = {"The PCAP filter to use."},
        defaultValue = "tcp port 443 and ip proto \\tcp"
    )
    private String filter;
    /**
     * Time (in seconds) before a new stats dump is created.
     */
    @Option(
        names = {"-w", "--stats-window"},
        description = {"Time (in seconds) before a new stats dump is created."},
        defaultValue = "60"
    )
    private int statsWindow;
    /**
     * Program runner indicator. This is set to false by the shutdown handler and will gracefully end execution with a stats dump.
     */
    private boolean doLoop = true;
    /**
     * Handle used to gather packet data.
     */
    private PcapHandle handle;
    /**
     * Hostname of the redis server used for cross-node communication.
     */
    @Option(
        names = {"-rh", "--redis-host"},
        defaultValue = "localhost",
        description = {"Hostname of the redis server used for cross-node communication"}
    )
    private String redisHost;
    /**
     * Port of the redis server used for cross-node communication.
     */
    @Option(
        names = {"-rp", "--redis-port"},
        defaultValue = "6379",
        description = {"Port of the redis server used for cross-node communication"}
    )
    private int redisPort;
    /**
     * Redis instance to register {@link edu.trevecca.flare.core.redis.RedisListener}s and to send {@link
     * edu.trevecca.flare.core.redis.RedisMessage}s.
     */
    static Redis redis;
    /**
     * The number of packets received which do not match the inbound or outbound {@link #DISCARD_CHECK} in the current window.
     */
    private final AtomicInteger badNets = new AtomicInteger();

    public static void main(String[] args) throws Exception {
        // Parse args (see above)
        // If everything works out OK, the call() method under this will be executed.
        CommandLine.call(new Main(), args);
    }

    public Void call() throws Exception {
        // Sanity check for people who can't read.
        if (this.interfaceName == null && !this.chooseInterface) {
            logger.severe("Interface name not supplied and choose option disabled!");
            System.exit(1);
        }

        // Choose an interface
        PcapNetworkInterface device = this.getNetworkDevice();
        if (device == null) {
            logger.severe("No device chosen!");
            System.exit(1);
        }
        logger.info("You chose: " + device.getName());

        // Graceful shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(this::finish));

        // Connect to Redis
        redis = Redis.builder(this.redisHost, this.redisPort).reconnect(true).build();
        redis.enable();

        // Set up PCAP
        int snapshotLength = 65536;
        int readTimeout = 50;
        Builder builder = new Builder(device.getName());
        builder.bufferSize(this.bufferSize).promiscuousMode(PromiscuousMode.PROMISCUOUS).timeoutMillis(readTimeout)
            .snaplen(snapshotLength);
        this.handle = builder.build();
        this.handle.setFilter(this.filter, BpfCompileMode.OPTIMIZE);

        // Main packet listen loop
        while (this.doLoop) {
            // Dump stats after window expires
            if (Instant.now().minusSeconds((long) this.statsWindow).isAfter(this.start)) {
                Instant finalStart = this.start;
                // Spawn a thread so stats dump doesn't slow down the main loop.
                (new Thread(
                    () -> StatsUtils.dumpStats(finalStart, new HashMap(this.outboundTraffic), new HashMap(this.inboundTraffic),
                                               this.statsWindow, this.badNets.get()
                                              ))).run();
                // Clear local cache
                badNets.set(0);
                this.outboundTraffic.clear();
                this.start = Instant.now();
            }

            // Listen for packets
            try {
                Packet packet = this.handle.getNextPacketEx();
                // Only care about IPv4 packets.
                if (packet.contains(IpV4Packet.class)) {
                    Inet4Address out = packet.get(IpV4Packet.class).getHeader().getDstAddr();
                    Inet4Address in = packet.get(IpV4Packet.class).getHeader().getSrcAddr();
                    byte[] outAddr = out.getAddress();
                    byte[] inAddr = in.getAddress();

                    // Only record addresses not inside the local network
                    if (!DISCARD_CHECK.test(outAddr)) {
                        this.outboundTraffic.putIfAbsent(out, new AtomicInteger());
                        this.outboundTraffic.get(out).addAndGet(packet.getHeader().length());
                    }
                    // Only record addresses not inside the local network
                    if (!DISCARD_CHECK.test(inAddr)) {
                        this.inboundTraffic.putIfAbsent(in, new AtomicInteger());
                        this.inboundTraffic.get(in).addAndGet(packet.getHeader().length());
                    }

                    // Scream loudly when we get a packet not meant for us
                    if (!DISCARD_CHECK.test(inAddr) && !DISCARD_CHECK.test(outAddr)) {
                        logger.severe(
                            "UH OH! Looks like we got a packet not matching to/from 172.16: src " + in.getHostAddress() + "  dest"
                            + out.getHostAddress());
                        badNets.incrementAndGet();
                    }

                }
            }
            catch (TimeoutException ex) {
                // Not handled
            }
            catch (EOFException ex) {
                ex.printStackTrace();
            }
        }

        return null;
    }

    /**
     * Graceful shutdown
     */
    private void finish() {
        // Stop the packet loop
        this.doLoop = false;

        try {
            logger.info("Shutting down...");

            // Wait a bit for dramatic effect
            Thread.sleep(400L);

            // Have to get a new logger since the old one has already been destroyed
            Logger shutdown = Logging.getLogger("Shutdown");

            // Dump stats and log debug data
            PcapStat stats = this.handle.getStats();
            shutdown.info("Packets received: " + stats.getNumPacketsReceived());
            shutdown.info("Packets dropped: " + stats.getNumPacketsDropped());
            shutdown.info("Packets dropped by interface: " + stats.getNumPacketsDroppedByIf());
            StatsUtils.dumpStats(this.start, this.outboundTraffic, this.inboundTraffic, this.statsWindow, this.badNets.get());

            // Close the handle
            this.handle.close();
        }
        catch (Exception ex) {
            ex.printStackTrace();
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
        catch (Exception ex) {
            ex.printStackTrace();
        }

        return device;
    }
}