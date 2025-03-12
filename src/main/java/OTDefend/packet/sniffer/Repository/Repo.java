package OTDefend.packet.sniffer.Repository;

import OTDefend.packet.sniffer.Service.packetAnalyzer;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

@Repository
public class Repo {

    @Autowired
    packetAnalyzer analyzer;

    public void networkSniffer(String nifName, int snapLen, int timeOut, int numberOfPacketCount){

        try {
            PcapNetworkInterface nif = Pcaps.getDevByName(nifName);

            if (nif == null) {
                System.out.println("Ağ arayüzü bulunamadı: " + nifName);
                return;
            }

            PcapNetworkInterface.PromiscuousMode mode = PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

            try (PcapHandle handle = nif.openLive(snapLen, mode, timeOut)) {
                System.out.println("Paket yakalamaya başlanıyor...");

                // Packet listening loop
                handle.loop(numberOfPacketCount, (PacketListener) packet -> {
                    System.out.println("Yakalanan Paket: " + packet);
                    analyzer.analyzePacket(packet);
                });
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}


