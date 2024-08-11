
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <syslog.h>
#include <cjson/cJSON.h>
#include <yaml.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <dirent.h>


#define JSON_FILE_NAME "groups.json"
#define DAEMON_PORT 12345
#define MESSAGE "Hello, multicast world!"
#define MAX_NAME_LENGTH 100
#define MAX_IP_LENGTH 16
#define MAX_USERS 100
#define MAX_GROUPS 50
#define BUFFER_SIZE 1024
#define MAX_RETRIES 5
#define RETRY_DELAY 1000000  // 1 second in microseconds
#define MAX_FILES 100
#define ADMIN_IP "192.168.43.151"

typedef struct {
    char name[MAX_NAME_LENGTH];
    char ip[MAX_IP_LENGTH];
} User;

typedef struct {
    char name[MAX_NAME_LENGTH];
    User users[MAX_USERS];
    int user_count;
    char multicast_ip[MAX_IP_LENGTH];
} Group;

Group groups[MAX_GROUPS];
int group_count = 0;

// File transfer structures
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

// Function declarations
char* get_hostname(const char *ip_address);
int is_valid_ip(const char *ip);
void perform_network_scan();
void parse_json();
void save_json();
void signal_user_daemon(const char* user_ip, const char* multicast_ip);
void send_multicast(const char* multicast_ip, const char* message);
void add_user(const char* group_name, const char* user_name, const char* user_ip);
void create_group(const char* group_name, const char* multicast_ip);
void remove_group(const char* group_name);
void print_groups();
void save_message_to_file(const char* message);
void send_message_to_group(const char* group_name, const char* message);
void calculate_md5(const void *data, size_t len, unsigned char *md5_sum);
int send_with_retry(int sock, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
int list_files(char *files[], int max_files);
void print_file_list(char *files[], int file_count);
int select_file(char *files[], int file_count);
int send_file(int sock, struct sockaddr_in *groupSock, const char *file_name);

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

int is_valid_ip(const char *ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

void perform_network_scan() {
    const char *command = "sudo arp-scan --localnet";
    FILE *fp = popen(command, "r");

    if (fp == NULL) {
        perror("popen");
        return;
    }

    char line[256];
    char ip_address[INET_ADDRSTRLEN];
    char *token;

    while (fgets(line, sizeof(line), fp) != NULL) {
        token = strtok(line, " \t");
        if (token && is_valid_ip(token)) {
            strncpy(ip_address, token, sizeof(ip_address));
            ip_address[sizeof(ip_address) - 1] = '\0'; 

            char *hostname = get_hostname(ip_address);
            printf("IP Address: %s, Hostname: %s\n", ip_address, hostname);
        }
    }

    pclose(fp);
}

void parse_json() {
    FILE* file = fopen(JSON_FILE_NAME, "r");
    if (!file) {
        printf("groups.json not found. Creating a new file with an empty structure.\n");
        file = fopen(JSON_FILE_NAME, "w");
        if (!file) {
            perror("Error creating file");
            return;
        }
        fprintf(file, "{\"groups\":[]}\n");
        fclose(file);
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* json_string = (char*)malloc(file_size + 1);
    fread(json_string, 1, file_size, file);
    fclose(file);

    json_string[file_size] = '\0';

    cJSON* root = cJSON_Parse(json_string);
    free(json_string);

    if (!root) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "JSON parsing error: %s\n", error_ptr);
        }
        return;
    }

    group_count = 0;

    cJSON* groups_json = cJSON_GetObjectItem(root, "groups");
    if (cJSON_IsArray(groups_json)) {
        cJSON* group_json = NULL;
        cJSON_ArrayForEach(group_json, groups_json) {
            if (group_count >= MAX_GROUPS) {
                fprintf(stderr, "Warning: Too many groups in the JSON file, ignoring extra groups.\n");
                break;
            }

            cJSON* name = cJSON_GetObjectItem(group_json, "name");
            cJSON* multicast_ip = cJSON_GetObjectItem(group_json, "multicast_ip");
            cJSON* users_json = cJSON_GetObjectItem(group_json, "users");

            if (cJSON_IsString(name) && cJSON_IsString(multicast_ip) && cJSON_IsArray(users_json)) {
                Group* current_group = &groups[group_count++];
                strncpy(current_group->name, name->valuestring, MAX_NAME_LENGTH);
                strncpy(current_group->multicast_ip, multicast_ip->valuestring, MAX_IP_LENGTH);
                current_group->user_count = 0;

                cJSON* user_json = NULL;
                cJSON_ArrayForEach(user_json, users_json) {
                    if (current_group->user_count >= MAX_USERS) {
                        fprintf(stderr, "Warning: Too many users in group '%s', ignoring extra users.\n", current_group->name);
                        break;
                    }

                    cJSON* user_name = cJSON_GetObjectItem(user_json, "name");
                    cJSON* user_ip = cJSON_GetObjectItem(user_json, "ip");

                    if (cJSON_IsString(user_name) && cJSON_IsString(user_ip)) {
                        User* current_user = &current_group->users[current_group->user_count++];
                        strncpy(current_user->name, user_name->valuestring, MAX_NAME_LENGTH);
                        strncpy(current_user->ip, user_ip->valuestring, MAX_IP_LENGTH);
                    }
                }
            }
        }
    } else {
        fprintf(stderr, "Error: 'groups' is not an array\n");
    }

    cJSON_Delete(root);
}

void save_json() {
    cJSON* root = cJSON_CreateObject();
    cJSON* groups_json = cJSON_CreateArray();
    cJSON_AddItemToObject(root, "groups", groups_json);

    for (int i = 0; i < group_count; i++) {
        cJSON* group_item = cJSON_CreateObject();
        cJSON_AddItemToArray(groups_json, group_item);

        cJSON_AddStringToObject(group_item, "name", groups[i].name);
        cJSON_AddStringToObject(group_item, "multicast_ip", groups[i].multicast_ip);

        cJSON* users = cJSON_CreateArray();
        cJSON_AddItemToObject(group_item, "users", users);

        for (int j = 0; j < groups[i].user_count; j++) {
            cJSON* user_item = cJSON_CreateObject();
            cJSON_AddItemToArray(users, user_item);

            cJSON_AddStringToObject(user_item, "name", groups[i].users[j].name);
            cJSON_AddStringToObject(user_item, "ip", groups[i].users[j].ip);
        }
    }

    char* json_string = cJSON_Print(root);
    FILE* file = fopen(JSON_FILE_NAME, "w");
    if (file) {
        fputs(json_string, file);
        fclose(file);
    } else {
        perror("Error opening file for writing");
    }
    cJSON_Delete(root);
    free(json_string);
}

void signal_user_daemon(const char* user_ip, const char* multicast_ip) {
    struct sockaddr_in server_addr;
    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DAEMON_PORT);
    inet_pton(AF_INET, user_ip, &server_addr.sin_addr);

    char message[BUFFER_SIZE];
    snprintf(message, sizeof(message), "Signal for multicast IP %s", multicast_ip);

    if (sendto(sockfd, message, strlen(message), 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("sendto failed");
    }

    close(sockfd);
}

void send_multicast(const char* multicast_ip, const char* message) {
    struct sockaddr_in groupSock;
    int sock;
    struct ip_mreq group;
    int ttl = 255; // Time-to-live for multicast packets

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&groupSock, 0, sizeof(groupSock));
    groupSock.sin_family = AF_INET;
    groupSock.sin_addr.s_addr = inet_addr(multicast_ip);
    groupSock.sin_port = htons(DAEMON_PORT);

    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("setsockopt failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (sendto(sock, message, strlen(message), 0, (struct sockaddr*)&groupSock, sizeof(groupSock)) < 0) {
        perror("sendto failed");
    }

    close(sock);
}

void add_user(const char* group_name, const char* user_name, const char* user_ip) {
    for (int i = 0; i < group_count; i++) {
        if (strcmp(groups[i].name, group_name) == 0) {
            if (groups[i].user_count >= MAX_USERS) {
                fprintf(stderr, "Error: User limit reached for group '%s'\n", group_name);
                return;
            }
            User* new_user = &groups[i].users[groups[i].user_count++];
            strncpy(new_user->name, user_name, MAX_NAME_LENGTH);
            strncpy(new_user->ip, user_ip, MAX_IP_LENGTH);
            printf("User %s added to group %s\n", user_name, group_name);
            signal_user_daemon(user_ip, groups[i].multicast_ip);
            save_json();
            return;
        }
    }
    fprintf(stderr, "Error: Group '%s' not found\n", group_name);
}

void create_group(const char* group_name, const char* multicast_ip) {
    if (group_count >= MAX_GROUPS) {
        fprintf(stderr, "Error: Maximum number of groups reached\n");
        return;
    }

    for (int i = 0; i < group_count; i++) {
        if (strcmp(groups[i].name, group_name) == 0) {
            fprintf(stderr, "Error: Group '%s' already exists\n", group_name);
            return;
        }
    }

    Group* new_group = &groups[group_count++];
    strncpy(new_group->name, group_name, MAX_NAME_LENGTH);
    strncpy(new_group->multicast_ip, multicast_ip, MAX_IP_LENGTH);
    new_group->user_count = 0;

    printf("Group '%s' created with multicast IP '%s'\n", group_name, multicast_ip);
    save_json();
}

void remove_group(const char* group_name) {
    int index = -1;
    for (int i = 0; i < group_count; i++) {
        if (strcmp(groups[i].name, group_name) == 0) {
            index = i;
            break;
        }
    }

    if (index == -1) {
        fprintf(stderr, "Error: Group '%s' not found\n", group_name);
        return;
    }

    for (int i = index; i < group_count - 1; i++) {
        groups[i] = groups[i + 1];
    }
    group_count--;
    save_json();
    printf("Group '%s' removed\n", group_name);
}

void print_groups() {
    for (int i = 0; i < group_count; i++) {
        printf("Group Name: %s\n", groups[i].name);
        printf("Multicast IP: %s\n", groups[i].multicast_ip);
        printf("Users:\n");
        for (int j = 0; j < groups[i].user_count; j++) {
            printf("  %s - %s\n", groups[i].users[j].name, groups[i].users[j].ip);
        }
        printf("\n");
    }
}

void save_message_to_file(const char* message) {
    FILE* file = fopen("messages.log", "a");
    if (file) {
        fprintf(file, "%s\n", message);
        fclose(file);
    } else {
        perror("Error opening message file");
    }
}

void send_message_to_group(const char* group_name, const char* message) {
    for (int i = 0; i < group_count; i++) {
        if (strcmp(groups[i].name, group_name) == 0) {
            send_multicast(groups[i].multicast_ip, message);
            save_message_to_file(message);
            return;
        }
    }
    fprintf(stderr, "Error: Group '%s' not found\n", group_name);
}

void calculate_md5(const void *data, size_t len, unsigned char *md5_sum) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, data, len);
    MD5_Final(md5_sum, &ctx);
}

int send_with_retry(int sock, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    int retries = 0;
    ssize_t sent_size;
    while (retries < MAX_RETRIES) {
        sent_size = sendto(sock, buf, len, flags, dest_addr, addrlen);
        if (sent_size < 0) {
            perror("sendto failed");
            retries++;
            usleep(RETRY_DELAY);
        } else {
            return 0; // success
        }
    }
    fprintf(stderr, "Error: Failed to send data after %d retries\n", MAX_RETRIES);
    return -1;
}

int list_files(char *files[], int max_files) {
    DIR *dir;
    struct dirent *entry;
    int count = 0;

    dir = opendir(".");
    if (!dir) {
        perror("opendir");
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) { // regular file
            if (count < max_files) {
                files[count] = strdup(entry->d_name);
                count++;
            } else {
                fprintf(stderr, "Warning: Maximum file limit reached\n");
                break;
            }
        }
    }

    closedir(dir);
    return count;
}

void print_file_list(char *files[], int file_count) {
    for (int i = 0; i < file_count; i++) {
        printf("%d: %s\n", i + 1, files[i]);
    }
}

int select_file(char *files[], int file_count) {
    int choice;
    printf("Select a file by number: ");
    scanf("%d", &choice);
    if (choice < 1 || choice > file_count) {
        printf("Invalid selection\n");
        return -1;
    }
    return choice - 1;
}

int send_file(int sock, struct sockaddr_in *groupSock, const char *file_name) {
    int file_fd;
    struct file_header header;
    struct data_packet packet;
    size_t bytes_read;
    off_t offset = 0;
    struct stat st;
    int packet_size;
    ssize_t sent_size;

    file_fd = open(file_name, O_RDONLY);
    if (file_fd < 0) {
        perror("open file");
        return -1;
    }

    if (fstat(file_fd, &st) < 0) {
        perror("fstat");
        close(file_fd);
        return -1;
    }

    // Prepare file header
    strncpy(header.filename, file_name, sizeof(header.filename));
    header.filesize = st.st_size;
    header.packet_count = (st.st_size + BUFFER_SIZE - 1) / BUFFER_SIZE; // Total number of packets
    calculate_md5(file_name, strlen(file_name), header.md5_checksum);

    // Send header
    if (send_with_retry(sock, &header, sizeof(header), 0, (struct sockaddr *)groupSock, sizeof(*groupSock)) < 0) {
        close(file_fd);
        return -1;
    }

    while ((bytes_read = pread(file_fd, packet.data, sizeof(packet.data), offset)) > 0) {
        packet.packet_number = offset / BUFFER_SIZE;
        packet.packet_length = bytes_read;
        calculate_md5(packet.data, bytes_read, packet.md5_checksum);

        packet_size = sizeof(packet.packet_number) + sizeof(packet.packet_length) + sizeof(packet.md5_checksum) + bytes_read;

        if (send_with_retry(sock, &packet, packet_size, 0, (struct sockaddr *)groupSock, sizeof(*groupSock)) < 0) {
            close(file_fd);
            return -1;
        }

        offset += bytes_read;
    }

    close(file_fd);
    return 0;
}

// Main function
// List groups and allow admin to select one
int select_group(char *selected_group_name) {
    printf("Select a group:\n");
    for (int i = 0; i < group_count; i++) {
        printf("%d. %s\n", i + 1, groups[i].name);
    }
    printf("Enter the number of the group: ");
    int choice;
    scanf("%d", &choice);
    if (choice < 1 || choice > group_count) {
        printf("Invalid choice.\n");
        return -1;
    }
    strcpy(selected_group_name, groups[choice - 1].name);
    return 0;
}

// Main function
int main() {
    openlog("group_manager", LOG_PID | LOG_CONS, LOG_USER);

    parse_json();

    int choice;
    char group_name[MAX_NAME_LENGTH], user_name[MAX_NAME_LENGTH], ip[MAX_IP_LENGTH], message[256];
    char *files[MAX_FILES];
    int file_count, selected_file;
    char selected_group[MAX_NAME_LENGTH];

    do {
        printf("\nGroup Management Menu:\n");
        printf("1. Add user to group\n");
        printf("2. Create new group\n");
        printf("3. Remove group\n");
        printf("4. Print all groups\n");
        printf("5. Save changes\n");
        printf("6. Send message to group\n");
        printf("7. Perform network scan\n");
        printf("8. Transfer file via multicast\n");
        printf("0. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                printf("Enter group name: ");
                scanf("%s", group_name);
                printf("Enter user name: ");
                scanf("%s", user_name);
                printf("Enter user IP: ");
                scanf("%s", ip);
                add_user(group_name, user_name, ip);
                break;
            case 2:
                printf("Enter new group name: ");
                scanf("%s", group_name);
                printf("Enter multicast IP: ");
                scanf("%s", ip);
                create_group(group_name, ip);
                break;
            case 3:
                printf("Enter group name to remove: ");
                scanf("%s", group_name);
                remove_group(group_name);
                break;
            case 4:
                print_groups();
                break;
            case 5:
                save_json();
                break;
            case 6:
                printf("Enter group name to send message to: ");
                scanf("%s", group_name);
                printf("Enter message to send: ");
                scanf(" %[^\n]", message);  // Read message with spaces
                send_message_to_group(group_name, message);
                break;
            case 7:
                perform_network_scan();
                break;
            case 8:
                if (select_group(selected_group) != 0) {
                    break;  // Exit if group selection failed
                }
                
                // Retrieve multicast IP of the selected group
                char multicast_ip[MAX_IP_LENGTH];
                for (int i = 0; i < group_count; i++) {
                    if (strcmp(groups[i].name, selected_group) == 0) {
                        strcpy(multicast_ip, groups[i].multicast_ip);
                        break;
                    }
                }

                struct in_addr localInterface;
                struct sockaddr_in groupSock;
                int sock;

                // Create a datagram socket
                sock = socket(AF_INET, SOCK_DGRAM, 0);
                if (sock < 0) {
                    perror("Opening datagram socket error");
                    exit(EXIT_FAILURE);
                }

                // Set socket to non-blocking mode
                int flags = fcntl(sock, F_GETFL, 0);
                fcntl(sock, F_SETFL, flags | O_NONBLOCK);

                // Initialize the group sockaddr structure
                memset(&groupSock, 0, sizeof(groupSock));
                groupSock.sin_family = AF_INET;
                groupSock.sin_addr.s_addr = inet_addr(multicast_ip);  // Use multicast IP from selected group
                groupSock.sin_port = htons(8888);  // Example port

                // Set local interface for outbound multicast datagrams
                localInterface.s_addr = inet_addr(ADMIN_IP);  // Replace with local interface address
                if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_IF, (char *)&localInterface, sizeof(localInterface)) < 0) {
                    perror("Setting local interface error");
                    close(sock);
                    exit(EXIT_FAILURE);
                }

                // List files in current directory
                file_count = list_files(files, MAX_FILES);
                if (file_count < 0) {
                    close(sock);
                    exit(EXIT_FAILURE);
                }

                // Print file list and get user selection
                print_file_list(files, file_count);
                selected_file = select_file(files, file_count);

                if (selected_file >= 0) {
                    printf("Sending file: %s\nTo Multicast: %s", files[selected_file],multicast_ip);
                    if (send_file(sock, &groupSock, files[selected_file]) < 0) {
                        fprintf(stderr, "Failed to send file: %s\n", files[selected_file]);
                    }
                }

                // Clean up
                for (int i = 0; i < file_count; i++) {
                    free(files[i]);
                }
                close(sock);
                break;
            case 0:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    } while (choice != 0);

    save_json();
    closelog();
    return 0;
}
