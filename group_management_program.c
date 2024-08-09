#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "group_management_constants.h"
#define DAEMON_PORT 12345 
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


void parse_yaml() {
    FILE* file = fopen(YAML_FILE_NAME, "r");
    yaml_parser_t parser;
    yaml_event_t event;

    if (!file) {
        perror("fopen");
        return;
    }

    if (!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Failed to initialize parser\n");
        fclose(file);
        return;
    }

    yaml_parser_set_input_file(&parser, file);

    Group* current_group = NULL;
    User* current_user = NULL;
    char* key = NULL;
    int in_groups = 0;
    int in_users = 0;

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            fprintf(stderr, "Parser error\n");
            break;
        }

        switch (event.type) {
            case YAML_SCALAR_EVENT:
                if (strcmp((char*)event.data.scalar.value, "groups") == 0) {
                    in_groups = 1;
                } else if (in_groups) {
                    if (key == NULL) {
                        key = strdup((char*)event.data.scalar.value);
                    } else {
                        if (current_user) {
                            if (strcmp(key, "name") == 0) {
                                strncpy(current_user->name, (char*)event.data.scalar.value, MAX_NAME_LENGTH);
                            } else if (strcmp(key, "ip") == 0) {
                                strncpy(current_user->ip, (char*)event.data.scalar.value, MAX_IP_LENGTH);
                            }
                        } else if (current_group) {
                            if (strcmp(key, "name") == 0) {
                                strncpy(current_group->name, (char*)event.data.scalar.value, MAX_NAME_LENGTH);
                            } else if (strcmp(key, "multicast_ip") == 0) {
                                strncpy(current_group->multicast_ip, (char*)event.data.scalar.value, MAX_IP_LENGTH);
                            }
                        }
                        free(key);
                        key = NULL;
                    }
                }
                break;

            case YAML_MAPPING_START_EVENT:
                if (in_groups && !current_group) {
                    if (group_count < MAX_GROUPS) {
                        current_group = &groups[group_count++];
                        current_group->user_count = 0;
                    } else {
                        fprintf(stderr, "Maximum number of groups reached.\n");
                        in_groups = 0;
                    }
                } else if (current_group && !current_user) {
                    current_user = &current_group->users[current_group->user_count++];
                }
                break;

            case YAML_MAPPING_END_EVENT:
                if (current_user) {
                    current_user = NULL;
                } else if (current_group) {
                    current_group = NULL;
                }
                break;

            case YAML_SEQUENCE_START_EVENT:
                if (in_groups && current_group && key && strcmp(key, "users") == 0) {
                    in_users = 1;
                }
                break;

            case YAML_SEQUENCE_END_EVENT:
                if (in_users) {
                    in_users = 0;
                }
                break;

            case YAML_STREAM_END_EVENT:
                break;

            default:
                break;
        }

        if (event.type != YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
        }
    } while (event.type != YAML_STREAM_END_EVENT);

    yaml_event_delete(&event);
    yaml_parser_delete(&parser);
    fclose(file);

}

void save_yaml() {
    FILE* file = fopen(YAML_FILE_NAME, "w");
    if (!file) {
        fprintf(stderr, "Failed to open file for writing: %s\n", YAML_FILE_NAME);
        return;
    }

    fprintf(file, "groups:\n");
    for (int i = 0; i < group_count; i++) {
        fprintf(file, "  - name: %s\n", groups[i].name);
        fprintf(file, "    multicast_ip: %s\n", groups[i].multicast_ip);
        fprintf(file, "    users:\n");
        for (int j = 0; j < groups[i].user_count; j++) {
            fprintf(file, "      - name: %s\n", groups[i].users[j].name);
            fprintf(file, "        ip: %s\n", groups[i].users[j].ip);
        }
    }

    fclose(file);
    printf("Changes saved to %s\n", YAML_FILE_NAME);
}

void signal_user_daemon(const char* user_ip, const char* multicast_ip) {
    int sock;
    struct sockaddr_in server_addr;
    char message[256];

    // Create UDP socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket creation failed");
        return;
    }

    memset(&server_addr, 0, sizeof(server_addr));

    // Set up the server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DAEMON_PORT);
    server_addr.sin_addr.s_addr = inet_addr(user_ip);

    // Prepare the message
    snprintf(message, sizeof(message), "JOIN %s", multicast_ip);

    // Send the message
    if (sendto(sock, message, strlen(message), 0,
               (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to send message to daemon");
    } else {
        printf("Signal sent to daemon at %s to join multicast group %s\n", user_ip, multicast_ip);
    }

    close(sock);
}

// Modified add_user function
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
        printf("\n");
    }
}

int main() {
    parse_yaml();
    int choice;
    char group_name[MAX_NAME_LENGTH], user_name[MAX_NAME_LENGTH], ip[MAX_IP_LENGTH];

    do {
        printf("\nGroup Management Menu:\n");
        printf("1. Add user to group\n");
        printf("2. Create new group\n");
        printf("3. Remove group\n");
        printf("4. Print all groups\n");
        printf("5. Save changes\n");
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
                save_yaml();
                break;
            case 0:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    } while (choice != 0);

    return 0;
}
