#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void execute_file(const char *filename) {
    char command[100];
    sprintf(command, "gcc %s -o temp_exec -lssl -lcrypto -lsodium -Wno-deprecated-declarations && ./temp_exec", filename);
    system(command);
}

int main() {
    int choice;
    char *files[] = {"MD5.c", "SHA512.c", "SHA256.c", "SHA256_SHA512.c", "SHA3_512.c"};

    while (1) {
        printf("Choose an option:\n");
        printf("1. MD5\n");
        printf("2. SHA512\n");
        printf("3. SHA256\n");
        printf("4. SAH256_512\n");
        printf("5. SHA3_512\n");
        printf("6. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        if (choice < 1 || choice > 6) {
            printf("Invalid choice. Please try again.\n");
            continue;
        }

        if (choice == 6) {
            printf("Exiting program.\n");
            break;
        }

        // Execute the selected file
        execute_file(files[choice - 1]);
    }

    return 0;
}

