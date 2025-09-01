#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define SERVER_PORT 12345
#define PSEUDO_HEADER_SIZE 12

// Compute the checksum used in IP and TCP headers
unsigned short compute_checksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        sum += *(unsigned char*)ptr;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}

// Structure for pseudo header used in TCP checksum calculation
struct pseudo_header {
    u_int32_t src_addr;
    u_int32_t dst_addr;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

int main() {
    // Create raw socket with TCP protocol
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("[-] Socket creation failed");
        return 1;
    }

    // We tell the kernel we will include IP header manually
    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("[-] setsockopt() failed");
        return 1;
    }

    char packet[4096];
    memset(packet, 0, 4096);

    struct iphdr *ip = (struct iphdr *) packet;
    struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));

    struct sockaddr_in dest_addr{};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, "127.0.0.1", &dest_addr.sin_addr);

    // Fill IP header fields
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip->id = htons(54321);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = inet_addr("127.0.0.1");
    ip->daddr = dest_addr.sin_addr.s_addr;
    ip->check = compute_checksum((unsigned short *)ip, sizeof(struct iphdr));

    // TCP SYN segment setup
    tcp->source = htons(1234);  // Random client port
    tcp->dest = htons(SERVER_PORT);
    tcp->seq = htonl(200);      // Initial sequence number
    tcp->ack_seq = 0;
    tcp->doff = 5;
    tcp->syn = 1;               // SYN flag set
    tcp->window = htons(8192);
    tcp->check = 0;

    // Create pseudo header for TCP checksum
    struct pseudo_header psh{};
    psh.src_addr = ip->saddr;
    psh.dst_addr = ip->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    char pseudo_packet[sizeof(pseudo_header) + sizeof(struct tcphdr)];
    memcpy(pseudo_packet, &psh, sizeof(psh));
    memcpy(pseudo_packet + sizeof(psh), tcp, sizeof(struct tcphdr));
    tcp->check = compute_checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

    std::cout << "[+] Sending SYN packet\n";
    if (sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
               (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("[-] sendto() failed");
        return 1;
    }

    // Wait for a SYN-ACK from server
    char buffer[4096];
    while (true) {
        ssize_t data_size = recv(sock, buffer, 4096, 0);
        if (data_size < 0) continue;

        struct iphdr *recv_ip = (struct iphdr *)buffer;
        struct tcphdr *recv_tcp = (struct tcphdr *)(buffer + recv_ip->ihl * 4);

        // Check if this is a SYN-ACK for our SYN
        if (recv_tcp->source == htons(SERVER_PORT) &&
            recv_tcp->dest == htons(1234) &&
            recv_tcp->syn == 1 && recv_tcp->ack == 1 &&
            ntohl(recv_tcp->ack_seq) == 201 &&
            ntohl(recv_tcp->seq) == 400) {
            
            std::cout << "[+] Received SYN-ACK from server\n";

            // Build ACK to complete 3-way handshake
            memset(packet, 0, 4096);
            ip = (struct iphdr *) packet;
            tcp = (struct tcphdr *) (packet + sizeof(struct iphdr));

            // IP header again
            ip->ihl = 5;
            ip->version = 4;
            ip->tos = 0;
            ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            ip->id = htons(54322);
            ip->frag_off = 0;
            ip->ttl = 64;
            ip->protocol = IPPROTO_TCP;
            ip->saddr = inet_addr("127.0.0.1");
            ip->daddr = dest_addr.sin_addr.s_addr;
            ip->check = compute_checksum((unsigned short *)ip, sizeof(struct iphdr));

            // Final ACK segment
            tcp->source = htons(1234);
            tcp->dest = htons(SERVER_PORT);
            tcp->seq = htonl(600);          // Next seq
            tcp->ack_seq = htonl(401);      // ACK for server’s seq + 1
            tcp->doff = 5;
            tcp->ack = 1;                   // ACK flag
            tcp->window = htons(8192);
            tcp->check = 0;

            memcpy(pseudo_packet + sizeof(psh), tcp, sizeof(struct tcphdr));
            tcp->check = compute_checksum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

            std::cout << "[+] Sending ACK to complete handshake\n";
            sendto(sock, packet, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                   (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            break;
        }
    }

    close(sock);
    std::cout << "[+] Handshake complete\n";
    return 0;
}
