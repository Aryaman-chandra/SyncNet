#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <ctype.h>

#define DAEMON_PORT 12345
#define BUFFER_SIZE 1024
#define FILE_PORT 8888

struct file_header {
    char filename[256];
    uint64_t filesize;
    uint32_t packet_count;
    unsigned char md5_checksum[MD5_DIGEST_LENGTH];
};

struct data_packet {
    uint64_t packet_number;
    uint32_t packet_length;
    unsigned char md5_checksum[MD5_DIGEST_LENGTH];
    char data[BUFFER_SIZE];
};

void handle_error(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void calculate_md5(const void *data, size_t len, unsigned char *md5_sum) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, len);
    MD5_Final(md5_sum, &ctx);
}

void print_checksum_difference(const unsigned char *expected, const unsigned char *calculated) {
    printf("Checksum mismatch details:\n");
    printf("Expected:  ");
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", expected[i]);
    }
    printf("\nCalculated: ");
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", calculated[i]);
    }
    printf("\nDifference: ");
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02x", expected[i] ^ calculated[i]);
    }
    printf("\n");
}

int receive_with_timeout(int sock, void *buf, size_t len, int flags, int timeout_sec) {
    fd_set readfds;
    struct timeval tv;
    int retries = 0;

    while (retries < 5) {
        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;

        int ready = select(sock + 1, &readfds, NULL, NULL, &tv);
        if (ready < 0) {
            perror("select");
            return -1;
        } else if (ready == 0) {
            fprintf(stderr, "Timeout occurred. Retrying...\n");
            retries++;
            continue;
        }

        ssize_t received = recv(sock, buf, len, flags);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000000);
                retries++;
            } else {
                perror("recv");
                return -1;
            }
        } else {
            return received;
        }
    }
    fprintf(stderr, "Failed to receive after %d retries\n", 5);
    return -1;
}

void print_packet_contents(const struct data_packet *packet) {
    printf("Packet %lu contents:\n", packet->packet_number);
    printf("Packet length: %u\n", packet->packet_length);
    
    printf("Hex dump:\n");
    for (uint32_t i = 0; i < packet->packet_length; i++) {
        printf("%02x ", (unsigned char)packet->data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    printf("ASCII representation:\n");
    for (uint32_t i = 0; i < packet->packet_length; i++) {
        printf("%c", isprint(packet->data[i]) ? packet->data[i] : '.');
        if ((i + 1) % 64 == 0) printf("\n");
    }
    printf("\n\n");
}

void start_file_receiver(const char *multicast_ip) {
    int sock;
    struct sockaddr_in localSock;
    struct ip_mreq group;
    char recvbuffer[BUFFER_SIZE];

    // Create a datagram socket
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("Opening datagram socket error");
        exit(EXIT_FAILURE);
    }
    printf("Opening datagram socket....OK.\n");

    // Enable SO_REUSEADDR
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(reuse)) < 0) {
        perror("Setting SO_REUSEADDR error");
        close(sock);
        exit(EXIT_FAILURE);
    }
    printf("Setting SO_REUSEADDR...OK.\n");

    // Bind to the proper port number with the IP address specified as INADDR_ANY
    memset((char *) &localSock, 0, sizeof(localSock));
    localSock.sin_family = AF_INET;
    localSock.sin_port = htons(FILE_PORT);
    localSock.sin_addr.s_addr = INADDR_ANY;
    if (bind(sock, (struct sockaddr*)&localSock, sizeof(localSock)) < 0) {
        perror("Binding datagram socket error");
        close(sock);
        exit(EXIT_FAILURE);
    }
    printf("Binding datagram socket...OK.\n");

    // Join the multicast group
    group.imr_multiaddr.s_addr = inet_addr(multicast_ip);
    group.imr_interface.s_addr = INADDR_ANY;
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char *)&group, sizeof(group)) < 0) {
        perror("Adding multicast group error");
        close(sock);
        exit(EXIT_FAILURE);
    }
    printf("Adding multicast group %s...OK.\n", multicast_ip);

    // Receive file header
    struct file_header header;
    if (receive_with_timeout(sock, &header, sizeof(header), 0, 5) < 0) {
        fprintf(stderr, "Failed to receive file header\n");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Verify header checksum
    unsigned char calculated_checksum[MD5_DIGEST_LENGTH];
    calculate_md5(&header, sizeof(header) - MD5_DIGEST_LENGTH, calculated_checksum);
    if (memcmp(calculated_checksum, header.md5_checksum, MD5_DIGEST_LENGTH) != 0) {
        fprintf(stderr, "File header checksum mismatch\n");
        print_checksum_difference(header.md5_checksum, calculated_checksum);
        //close(sock);
        //exit(EXIT_FAILURE);
    }

    printf("Receiving file: %s\n", header.filename);
    printf("File size: %.2f MB\n", (double)header.filesize / (1024 * 1024));

    // Open file for writing
    FILE *fp = fopen(header.filename, "wb");
    if (fp == NULL) {
        perror("Error opening file for writing");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Receive file contents
    struct data_packet packet;
    uint64_t received_packets = 0;
    uint64_t total_bytes_received = 0;

    while (received_packets < header.packet_count) {
        ssize_t bytes_received = receive_with_timeout(sock, &packet, sizeof(packet), 0, 5);
        if (bytes_received < 0) {
            fprintf(stderr, "Failed to receive data packet\n");
            fclose(fp);
            close(sock);
            exit(EXIT_FAILURE);
        }

        // Verify packet checksum
        calculate_md5(packet.data, packet.packet_length, calculated_checksum);
        if (memcmp(calculated_checksum, packet.md5_checksum, MD5_DIGEST_LENGTH) != 0) {
            fprintf(stderr, "Data packet checksum mismatch for packet %lu\n", packet.packet_number);
            print_checksum_difference(packet.md5_checksum, calculated_checksum);
            continue;  // Skip this packet and hope for retransmission
        }

        // Print packet contents
        print_packet_contents(&packet);

        // Write packet data to file
        size_t written = fwrite(packet.data, 1, packet.packet_length, fp);
        if (written != packet.packet_length) {
            perror("Error writing to file");
            fclose(fp);
            close(sock);
            exit(EXIT_FAILURE);
        }

        received_packets++;
        total_bytes_received += packet.packet_length;

        if (received_packets % 1000 == 0) {
            printf("Received %lu packets (%.2f%%)\n", received_packets,
                   (double)received_packets / header.packet_count * 100);
        }
    }

    printf("File transfer complete. Received %lu packets.\n", received_packets);
    printf("Total bytes received: %lu\n", total_bytes_received);

    fclose(fp);
    close(sock);
}

int main() {
    int sockfd;
    struct sockaddr_in addr;
    char recv_buffer[BUFFER_SIZE];
    struct sockaddr_in cli_addr;
    socklen_t addr_len = sizeof(cli_addr);
    ssize_t recv_len;

    // Create a UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        handle_error("Socket creation failed");
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(DAEMON_PORT);

    // Bind the socket
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        handle_error("Bind failed");
    }

    printf("Daemon listening for signals on port %d...\n", DAEMON_PORT);

    while (1) {
        // Receive messages from clients
        recv_len = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer) - 1, 0, (struct sockaddr*)&cli_addr, &addr_len);
        if (recv_len < 0) {
            perror("recvfrom failed");
            continue;
        }

        recv_buffer[recv_len] = '\0'; // Null-terminate the received message
        printf("Received message: %s\n", recv_buffer);

        // Extract multicast IP from the message
        char multicast_ip[INET_ADDRSTRLEN];
        if (sscanf(recv_buffer, "Signal for multicast IP %s", multicast_ip) == 1) {
            printf("Starting file receiver for multicast IP %s\n", multicast_ip);
            start_file_receiver(multicast_ip);
        } else {
            fprintf(stderr, "Unexpected message format: %s\n", recv_buffer);
        }
    }

    close(sockfd);
    return 0;
}
