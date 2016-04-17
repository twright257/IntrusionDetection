import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
 * ScannerFinder is used to read through a pcap file that is taken as a command line argument and print the IP 
 * addresses that send more than three times as many SYN requests as the SYNACK that they receive. 
 *  
 * Tyler Wright
 * March 22, 2015
 * 
 */
public class IDS {
	private String host; 
	private boolean stateless; 
	private String proto; 
	private String hostPort; 
	private String attackerPort; 
	private String attacker; 
	private String fromHost; 
	private String toHost; 
	private final String POLICY; 
	private final String PCAP_FILENAME; 
	private final StringBuilder errbuf = new StringBuilder();
	private Pcap pcap;
	
	//constructor
	public IDS(String filePath, String policy) {
		PCAP_FILENAME = filePath; 
		POLICY = policy; 
		pcap = Pcap.openOffline(PCAP_FILENAME, errbuf);
		readPolicy(); 
	}
	
	//method for parsing pcap file and printing out up address of possible port scanners
	public void parsePCAP() {
		//if pcap empty, print file error and return 
		if (pcap == null) {
			System.err.println(errbuf); // Error is stored in errbuf if any
			return;
		}
		final PcapPacket packet = new PcapPacket(JMemory.POINTER);
		final Tcp tcp = new Tcp();
		//loop through entire file, getting each packet
		pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {
			final Tcp tcp = new Tcp();
			final Ip4 ip = new Ip4();
			Payload payload = new Payload();
			//get next packet
			public void nextPacket(JPacket packet, StringBuilder errbuf) {
				Tcp tcp = new Tcp();
				Udp udp = new Udp(); 

				byte[] sIP = new byte[4];
				byte[] dIP = new byte[4];
				String sourceIP = "";
				String destIP = "";
				//if packet has ip and tcp header, examine further
				if (proto.equals("tcp") && packet.hasHeader(ip) && packet.hasHeader(tcp)) {
					sIP = packet.getHeader(ip).source();
					sourceIP = org.jnetpcap.packet.format.FormatUtils.ip(sIP);	//source ip address as string 
					dIP = packet.getHeader(ip).destination();
					destIP = org.jnetpcap.packet.format.FormatUtils.ip(dIP);	//destination ip address as string 
					if (destIP.equals(host)) {
						System .out.println(destIP);
						JBuffer p = tcp.peerPayloadTo(packet); 
						StringBuilder sb = new StringBuilder(); 
						p.getUTF8String(0, sb, p.size()); 
						String contents = sb.toString(); 
						if (contents != null && contents.contains(toHost)) {
							System.out.println("WARNING!");
						}
						//String payloadContents = payload.getUTF8String(0, payload.size()); 
						//System .out.println(payloadContents);
					}
					//if packet contains only SYN, increment value for sender IP
					if (tcp.flags_SYN() && !tcp.flags_ACK()) {

					//packet contains SYN and ACK, decrement value for receiving IP
					} else if (tcp.flags_SYN()) {

					}
				}
			}
			
		}, errbuf);

		pcap.close();
	}
	
	public void readPolicy() {
		try (BufferedReader br = new BufferedReader(new FileReader(POLICY))) {
		    String line;
		    while ((line = br.readLine()) != null) {
		    	String[] lineVals = line.split("="); 
		    	switch(lineVals[0]) {
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
			    		toHost = lineVals[1]; 
		    	}
		    }
		    System.out.println(host + stateless + proto + hostPort + attackerPort + attacker + toHost);
		} catch (FileNotFoundException e) {
			System.err.println("FILE NOT FOUND");
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static void main(String[] args) {
		IDS s = new IDS(args[0], args[1]); 
		s.parsePCAP(); 
	}
}