package OTDefend.packet.sniffer;

import OTDefend.packet.sniffer.Repository.Repo;
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

		Repo repo = context.getBean(Repo.class);
		String nifName = "\\Device\\NPF_{B2657CF7-908E-467F-92D2-40EACED5246E}";

		int snapLen = 65536;

		int timeout = 10;

		int numberOfPackets = 10;

		repo.networkSniffer(nifName, snapLen, timeout, numberOfPackets);


	}
}