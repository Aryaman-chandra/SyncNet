#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <yaml.h>
#include <cjson/cJSON.h>
#include "group_management_constants.h"


#define JSON_FILE_NAME "groups.json"
#define DAEMON_PORT 12345
#define MESSAGE "Hello, multicast world!"

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

    // Clear existing groups
    group_count = 0;

    // Parse groups from JSON
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
        printf("Changes saved to %s\n", JSON_FILE_NAME);
    } else {
        fprintf(stderr, "Error opening file for writing\n");
    }

    free(json_string);
    cJSON_Delete(root);
}

void signal_user_daemon(const char* user_ip, const char* multicast_ip) {
    int sock;
    struct sockaddr_in server_addr;
    char message[256];

    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DAEMON_PORT);


  server_addr.sin_addr.s_addr = inet_addr(user_ip);

    snprintf(message, sizeof(message), "JOIN %s", multicast_ip);

    if (sendto(sock, message, strlen(message), 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send message to daemon");
    } else {
        printf("Signal sent to daemon at %s to join multicast group %s\n", user_ip, multicast_ip);
    }

    close(sock);
}

void send_multicast(const char* multicast_ip, const char* message) {
    int sockfd;
    struct sockaddr_in addr;
    int message_len = strlen(message);
    int ttl = 255;  // Set TTL for multicast

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        syslog(LOG_ERR, "Socket creation failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Set TTL for multicast
    if (setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) < 0) {
        syslog(LOG_ERR, "setsockopt for TTL failed: %s", strerror(errno));
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(multicast_ip);
    addr.sin_port = htons(DAEMON_PORT);

    if (sendto(sockfd, message, message_len, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "sendto failed: %s", strerror(errno));
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    syslog(LOG_INFO, "Message sent to %s: %s", multicast_ip, message);

    close(sockfd);
}


void add_user(const char* group_name, const char* user_name, const char* user_ip) {
    for (int i = 0; i < group_count; i++) {
        if (strcmp(groups[i].name, group_name) == 0) {
            if (groups[i].user_count < MAX_USERS) {
                User* new_user = &groups[i].users[groups[i].user_count++];

             strncpy(new_user->name, user_name, MAX_NAME_LENGTH);
                strncpy(new_user->ip, user_ip, MAX_IP_LENGTH);
                printf("User added successfully.\n");

                // Signal the user daemon to join the multicast group
                signal_user_daemon(user_ip, groups[i].multicast_ip);
            } else {
                fprintf(stderr, "Group is full. Cannot add more users.\n");
            }
            return;
        }
    }
    fprintf(stderr, "Group not found.\n");
}

void create_group(const char* group_name, const char* multicast_ip) {
    if (group_count < MAX_GROUPS) {
        Group* new_group = &groups[group_count++];
        strncpy(new_group->name, group_name, MAX_NAME_LENGTH);
        strncpy(new_group->multicast_ip, multicast_ip, MAX_IP_LENGTH);
        new_group->user_count = 0;
        printf("Group created successfully.\n");
    } else {
        fprintf(stderr, "Maximum number of groups reached.\n");
    }
}

void remove_group(const char* group_name) {
    for (int i = 0; i < group_count; i++) {
        if (strcmp(groups[i].name, group_name) == 0) {
            for (int j = i; j < group_count - 1; j++) {
                groups[j] = groups[j + 1];
            }
            group_count--;
            printf("Group removed successfully.\n");
            return;
        }
    }
    fprintf(stderr, "Group not found.\n");
}

void print_groups() {
    for (int i = 0; i < group_count; i++) {
        printf("Group: %s (Multicast IP: %s)\n", groups[i].name, groups[i].multicast_ip);
        for (int j = 0; j < groups[i].user_count; j++) {
            printf("  User: %s (IP: %s)\n", groups[i].users[j].name, groups[i].users[j].ip);
       }
    }
}

void save_message_to_file(const char* message) {
    FILE* file = fopen("message.txt", "w");
    if (!file) {
        fprintf(stderr, "Failed to open file for writing: message.txt\n");
        return;
    }

    fprintf(file, "%s\n", message);
    fclose(file);
}

void send_message_to_group(const char* group_name, const char* message) {
    for (int i = 0; i < group_count; i++) {
        if (strcmp(groups[i].name, group_name) == 0) {
            save_message_to_file(message);
            send_multicast(groups[i].multicast_ip, message);
            return;
        }
    }
    fprintf(stderr, "Group not found.\n");
}


int main() {
    openlog("administrator", LOG_PID | LOG_CONS, LOG_USER);

    parse_json();
    int choice;
    char group_name[MAX_NAME_LENGTH], user_name[MAX_NAME_LENGTH], ip[MAX_IP_LENGTH], message[256];

    do {
        printf("\nGroup Management Menu:\n");
        printf("1. Add user to group\n");
        printf("2. Create new group\n");
        printf("3. Remove group\n");
        printf("4. Print all groups\n");
        printf("5. Save changes\n");
        printf("6. Send message to group\n");
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
            case 0:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    } while (choice != 0);

    closelog();

    return 0;
}
