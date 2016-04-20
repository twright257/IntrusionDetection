import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jnetpcap.Pcap;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JFlow;
import org.jnetpcap.packet.JFlowKey;
import org.jnetpcap.packet.JFlowMap;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.JScanner;
import org.jnetpcap.packet.Payload;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.format.XmlFormatter;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Http;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

/**
 * ScannerFinder is used to read through pcap and policy files that are taken as command
 * line arguments and print a warning message as well as the potential attacker's ip if 
 * the policy is matched. 
 * 
 * Tyler Wright April 19, 2016
 * 
 */
public class IDS {
	private String host;
	private boolean stateless;
	private String proto = "none";
	private String hostPort;
	private String attackerPort;
	private String attacker;
	private String fromHost;
	private String toHost2;
	private String toHost;
	private Pattern pattern;
	private Pattern pattern2;
	private Matcher matcher;
	private Matcher matcher2;
	private final String POLICY;
	private final String PCAP_FILENAME;
	private final StringBuilder errbuf = new StringBuilder();
	private Pcap pcap;
	private HashMap ipHash = new HashMap();

	/*
	 * constructor
	 * @params: policy = path of policy file, filePath = path of pcap file
	 */
	public IDS(String policy, String filePath) {
		PCAP_FILENAME = filePath;
		POLICY = policy;
		pcap = Pcap.openOffline(PCAP_FILENAME, errbuf);
		setPolicy();
	}

	/*
	 * method for reading in packets from pcap file
	 */
	public void parsePCAP() {
		// if pcap empty, print file error and return
		if (pcap == null) {
			System.err.println(errbuf); // Error is stored in errbuf if any
			return;
		}
		final PcapPacket packet = new PcapPacket(JMemory.POINTER);
		final Tcp tcp = new Tcp();
		final Udp udp = new Udp();
		// loop through entire file, getting each packet
		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {
			final Tcp tcp = new Tcp();
			final Ip4 ip = new Ip4();
			Payload payload = new Payload();

			// get next packet
			public void nextPacket(JPacket packet, StringBuilder errbuf) {
				// if packet has correct headers, examine further
				if ((proto.equals("none") || proto.equals("tcp")) && packet.hasHeader(ip) && packet.hasHeader(tcp)) {
					checkTCP(packet, tcp, ip);
				} else if (packet.hasHeader(ip) && packet.hasHeader(udp)) {
					checkUDP(packet, udp, ip);
				}

			}
		}, errbuf);
		pcap.close();
	}

	/*
	 * methods for checking tcp packets as well as stateful
	 */
	private void checkTCP(JPacket packet, Tcp tcp, Ip4 ip) {
		byte[] sIP = new byte[4];
		byte[] dIP = new byte[4];
		String sourceIP = "";
		String destIP = "";
		sIP = packet.getHeader(ip).source();
		sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
		dIP = packet.getHeader(ip).destination();
		destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
		// check if packet matches policy
		if (destIP.equals(host) && (attackerPort.equals("any") || attackerPort.equals(String.valueOf(tcp.source())))
				&& (hostPort.equals("any") || hostPort.equals(String.valueOf(tcp.destination())))) {
			// save packet contents as string
			JBuffer p = tcp.peerPayloadTo(packet);
			StringBuilder sb = new StringBuilder();
			p.getUTF8String(0, sb, p.size());
			String contents = sb.toString();
			if (stateless) {
				matcher = pattern.matcher(contents);
				// packet contents match policy regex
				if (matcher.find()) {
					System.out.println("WARNING!!! " + sourceIP);

				}
			// stateful content check. save and concat packets by sender ip
			} else {
				if (ipHash.containsKey(sourceIP)) {
					String synVal = (String) (ipHash.get(sourceIP));
					synVal += contents.trim();
					ipHash.put(sourceIP, synVal);
					matcher = pattern.matcher(synVal);
					matcher2 = pattern2.matcher(synVal);
					if (matcher.find() || matcher2.find()) {
						System.out.println("WARNING!!! " + sourceIP);
						ipHash.remove(sourceIP);
					}
				} else {
					ipHash.put(sourceIP, contents.trim());
				}
			}
		}
	}

	/*
	 * method for checking udp packets
	 */
	private void checkUDP(JPacket packet, Udp udp, Ip4 ip) {
		byte[] sIP = new byte[4];
		byte[] dIP = new byte[4];
		String sourceIP = "";
		String destIP = "";
		sIP = packet.getHeader(ip).source();
		sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);
		dIP = packet.getHeader(ip).destination();
		destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);
		String c = packet.toString();
		// check if packet matches policy
		if (destIP.equals(host) && (attackerPort.equals("any") || attackerPort.equals(String.valueOf(udp.source())))
				&& (hostPort.equals("any") || hostPort.equals(String.valueOf(udp.destination())))) {
			// save packet contents as string
			JBuffer p = udp.peerPayloadTo(packet);
			StringBuilder sb = new StringBuilder();
			p.getUTF8String(0, sb, p.size());
			String contents = sb.toString();
			matcher = pattern.matcher(contents);
			// packet contents match policy regex
			if (matcher.find()) {
				System.out.println("WARNING!!! " + sourceIP);
			}
		}
	}

	/*
	 * method for reading in and setting policy values
	 */
	private void setPolicy() {
		File file = new File(POLICY);
		try (BufferedReader br = new BufferedReader(new FileReader(file))) {
			String line;
			while ((line = br.readLine()) != null) {
				StringBuffer stringBuffer = new StringBuffer();
				stringBuffer.append(line);
				line = stringBuffer.toString();
				String[] lineVals = line.split("=");
				switch (lineVals[0]) {
				case "host":
					host = lineVals[1];
					break;
				case "type":
					if (lineVals[1].equals("stateless")) {
						stateless = true;
					} else {
						stateless = false;
					}
					break;
				case "proto":
					proto = lineVals[1];
					break;
				case "host_port":
					hostPort = lineVals[1];
					break;
				case "attacker_port":
					attackerPort = lineVals[1];
					break;
				case "attacker":
					attacker = lineVals[1];
					break;
				case "to_host":
					toHost = lineVals[1].replace("\"", "");
					toHost2 = toHost;
					if (!stateless) {
						toHost2 = ".*?" + toHost + ".*";
						toHost2 = toHost.replaceAll("\\s", "");
					}
					pattern = Pattern.compile(toHost);
					pattern2 = Pattern.compile(toHost2);
				}
			}
		} catch (FileNotFoundException e) {
			System.err.println("FILE NOT FOUND");
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String[] args) {
		IDS s = new IDS(args[0], args[1]);
		s.parsePCAP();
	}
}