package OTDefend.packet.sniffer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

@SpringBootApplication
public class Application {

	public static void main(String[] args) {
		ApplicationContext context = SpringApplication.run(Application.class, args);

		try {
			// Select the network interface
			String nifName = "\\Device\\NPF_{B2657CF7-908E-467F-92D2-40EACED5246E}";
			PcapNetworkInterface nif = Pcaps.getDevByName(nifName);

			if (nif == null) {
				System.out.println("Ağ arayüzü bulunamadı: " + nifName);
				return;
			}

			// Create a PcapHandle for packet capture
			int snapLen = 65536;
			PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;
			int timeout = 10;

			try (PcapHandle handle = nif.openLive(snapLen, mode, timeout)) {
				System.out.println("Paket yakalamaya başlanıyor...");

				// Packet listening loop
				handle.loop(10, (PacketListener) packet -> {
					System.out.println("Yakalanan Paket: " + packet);
					analyzePacket(packet);
				});
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	// Signature Analyzer - Compares packet data against known signatures
	private static void analyzePacket(Packet packet) {
		if (packet.getPayload() == null) return;

		byte[] payload = packet.getPayload().getRawData();
		String readableData = new String(payload, StandardCharsets.UTF_8);

		// List of known attack signatures or suspicious patterns
		List<String> signatures = Arrays.asList(
				"malicious-string",  // Example malware signature
				"SQL Injection",     // SQL Injection signature
				"cmd.exe",           // Windows command execution
				"wget",              // Remote file download
				"nc -e /bin/sh",     // Netcat reverse shell
				"password",          // Leaked password attempt
				"Authorization: Basic",  // Basic Auth (can be checked for brute-force attempts)
				"alert('XSS')"       // XSS attack signature
		);

		// Check if the packet matches any of the signatures
		for (String signature : signatures) {
			if (readableData.contains(signature)) {
				System.out.println("ALERT! Suspicious packet detected with signature: " + signature);
			}
		}

		if (packet.contains(UdpPacket.class)) {
			UdpPacket udpPacket = packet.get(UdpPacket.class);
			System.out.println("UDP Verisi: " + udpPacket);
		}

		if (packet.contains(TcpPacket.class)) {
			TcpPacket tcpPacket = packet.get(TcpPacket.class);
			System.out.println("TCP Verisi: " + tcpPacket);
		}
	}
}