#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define MAX_FIELD_SIZE 255
#define BUFFER_SIZE 1024

// Custom write function for libcurl
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t total_size = size * nmemb;
    char *buffer = (char *)userp;
    
    // Append the received data to the buffer
    strncat(buffer, contents, total_size);
    
    return total_size;
}

// Function to handle GET requests and parse JSON response
void get_groups(char *buffer, size_t buffer_size) {
    CURL *curl;
    CURLcode res;
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:5000/organization_groups");
        
        // Set up the custom write function
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, buffer);
        curl_easy_setopt(curl, CURLOPT_BUFFERSIZE, buffer_size);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "GET request failed: %s\n", curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);
    }
}

// Function to handle POST requests
// Function to handle POST requests
void apply_for_group(const char *group_name) {
    CURL *curl;
    CURLcode res;
    char ip_address[MAX_FIELD_SIZE + 1];
    char post_fields[BUFFER_SIZE];
    char response_buffer[BUFFER_SIZE] = {0};

    printf("Enter your IP address (max %d characters): ", MAX_FIELD_SIZE);
    fgets(ip_address, sizeof(ip_address), stdin);
    ip_address[strcspn(ip_address, "\n")] = 0; // Remove newline character
    if (strlen(ip_address) > MAX_FIELD_SIZE) {
        ip_address[MAX_FIELD_SIZE] = '\0'; // Ensure it’s null-terminated
    }

    int written = snprintf(post_fields, sizeof(post_fields), "{\"group_name\":\"%s\", \"ipAddress\":\"%s\"}", group_name, ip_address);
    if (written >= sizeof(post_fields)) {
        fprintf(stderr, "Warning: Output was truncated. Buffer size may be insufficient.\n");
    }

    curl = curl_easy_init();
    if(curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:5000/submit_request");
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        // Use a custom write function to capture the response but not print it
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, response_buffer);

        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
            fprintf(stderr, "POST request failed: %s\n", curl_easy_strerror(res));
        } else {
            // Instead of printing the JSON response, just print a custom success message
            printf("Request submitted successfully.\n");
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
}


int main() {
    int choice;
    char buffer[BUFFER_SIZE] = {0};

    while (1) {
        printf("1. View Groups List\n");
        printf("2. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);
        getchar(); // Consume newline character

        switch (choice) {
            case 1:
                get_groups(buffer, sizeof(buffer)); // Fetch and print groups list

                struct json_object *parsed_json = json_tokener_parse(buffer);
                struct json_object *groups;
                size_t n_groups;
                size_t i;

                if (json_object_object_get_ex(parsed_json, "groups", &groups)) {
                    n_groups = json_object_array_length(groups);
                    printf("Groups List:\n");

                    for (i = 0; i < n_groups; i++) {
                        struct json_object *group = json_object_array_get_idx(groups, i);
                        struct json_object *group_name;

                        if (json_object_object_get_ex(group, "name", &group_name)) {
                            printf("- %s\n", json_object_get_string(group_name));
                        }
                    }

                    // Allow the user to enter a group name to apply for
                    char group_name[MAX_FIELD_SIZE + 1];
                    printf("Enter the name of the group you want to apply for (or 'exit' to return): ");
                    fgets(group_name, sizeof(group_name), stdin);
                    group_name[strcspn(group_name, "\n")] = 0; // Remove newline character

                    if (strcmp(group_name, "exit") != 0) {
                        int group_exists = 0;
                        for (i = 0; i < n_groups; i++) {
                            struct json_object *group = json_object_array_get_idx(groups, i);
                            struct json_object *group_name_existing;

                            if (json_object_object_get_ex(group, "name", &group_name_existing)) {
                                if (strcmp(json_object_get_string(group_name_existing), group_name) == 0) {
                                    group_exists = 1;
                                    break;
                                }
                            }
                        }

                        if (group_exists) {
                            // Apply for the specified group
                            apply_for_group(group_name);
                        } else {
                            printf("The group '%s' does not exist.\n", group_name);
                        }
                    }
                } else {
                    fprintf(stderr, "No 'groups' key found in JSON.\n");
                }

                json_object_put(parsed_json); // Free memory
                break;
            case 2:
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }

    return 0;
}