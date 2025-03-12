package OTDefend.packet.sniffer.Service;

import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

@Service
public class packetAnalyzer {

    public static void analyzePacket(Packet packet) {
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
