#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

// Function to perform reverse DNS lookup
char* get_hostname(const char *ip_address) {
    struct addrinfo hints, *res;
    static char hostname[1024];
    int err;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((err = getaddrinfo(ip_address, NULL, &hints, &res)) != 0) {
        snprintf(hostname, sizeof(hostname), "Unknown");
        return hostname;
    }

    if (res->ai_addr) {
        if (getnameinfo(res->ai_addr, res->ai_addrlen, hostname, sizeof(hostname), NULL, 0, NI_NAMEREQD) != 0) {
            snprintf(hostname, sizeof(hostname), "Unknown");
        }
    } else {
        snprintf(hostname, sizeof(hostname), "Unknown");
    }

    freeaddrinfo(res);
    return hostname;
}

// Function to check if a string is a valid IP address
int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

int main() {
    const char *command = "sudo arp-scan --localnet"; // Adjust the interface and network range as needed
    FILE *fp = popen(command, "r");

    if (fp == NULL) {
        perror("popen");
        exit(EXIT_FAILURE);
    }

    char line[256];
    char ip_address[INET_ADDRSTRLEN];
    char *token;

    while (fgets(line, sizeof(line), fp) != NULL) {
        // Extract IP address using space as a delimiter
        token = strtok(line, " \t");
        if (token && is_valid_ip(token)) {
            strncpy(ip_address, token, sizeof(ip_address));
            ip_address[sizeof(ip_address) - 1] = '\0'; // Ensure null-termination

            // Perform reverse DNS lookup
            char *hostname = get_hostname(ip_address);

            // Print IP address and hostname
            printf("IP Address: %s, Hostname: %s\n", ip_address, hostname);
        }
    }

    pclose(fp);
    return 0;
}
