#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAX_USERS 10
#define USERNAME_LENGTH 20
#define PASSWORD_LENGTH (SHA256_DIGEST_LENGTH * 2) // Twice the length of SHA256 hash in hexadecimal
#define MAX_LOGIN_ATTEMPTS 3
#define MAX_QUESTION_LENGTH 100
#define MAX_ANSWER_LENGTH 50

typedef struct {
    char username[USERNAME_LENGTH];
    unsigned char password_hash[PASSWORD_LENGTH + 1]; // Additional space for null terminator
    char mfa_code[7]; // Six-digit MFA code + null terminator
    char personal_question[MAX_QUESTION_LENGTH];
    char personal_answer[MAX_ANSWER_LENGTH];
} User;

User users[MAX_USERS];
int num_users = 0;

// Function to securely hash a password using SHA-256
void hash_password(const char *password, unsigned char *hashed_password) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md = EVP_sha256();

    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, password, strlen(password));
    EVP_DigestFinal_ex(mdctx, hashed_password, NULL);
    EVP_MD_CTX_free(mdctx);
}

}

void register_user(const char *username, const char *password, const char *mfa_code, const char *question, const char *answer) {
    if (num_users >= MAX_USERS) {
        printf("Maximum number of users reached.\n");
        return;
    }

    if (strlen(username) >= USERNAME_LENGTH || strlen(mfa_code) != 6 || strlen(question) >= MAX_QUESTION_LENGTH || strlen(answer) >= MAX_ANSWER_LENGTH) {
        printf("Invalid input.\n");
        return;
    }

    // Hash the password before storing
    unsigned char hashed_password[PASSWORD_LENGTH + 1];
    hash_password(password, hashed_password);

    strcpy(users[num_users].username, username);
    memcpy(users[num_users].password_hash, hashed_password, PASSWORD_LENGTH + 1);
    strcpy(users[num_users].mfa_code, mfa_code);
    strcpy(users[num_users].personal_question, question);
    strcpy(users[num_users].personal_answer, answer);
    num_users++;

    printf("User registered successfully.\n");
}

int login(const char *username, const char *password) {
    int attempts_left = MAX_LOGIN_ATTEMPTS;
    while (attempts_left > 0) {
        for (int i = 0; i < num_users; i++) {
            if (strcmp(users[i].username, username) == 0) {
                // Hash the provided password for comparison
                unsigned char hashed_password[PASSWORD_LENGTH + 1];
                hash_password(password, hashed_password);

                if (memcmp(users[i].password_hash, hashed_password, PASSWORD_LENGTH + 1) == 0) {
                    // Login successful
                    printf("Login successful.\n");
                    return 1;
                } else {
                    attempts_left--;
                    if (attempts_left > 0) {
                        printf("Incorrect password. Attempts left: %d\n", attempts_left);
                        printf("Please try again.\n");
                    } else {
                        printf("Max login attempts reached. Account locked.\n");
                        return 0;
                    }
                }
            }
        }
        printf("User not found.\n");
        return 0;
    }
}

int main() {
    char username[USERNAME_LENGTH];
    char password[MAX_ANSWER_LENGTH + 1]; // Additional space for null terminator
    char mfa_code[7];
    char question[MAX_QUESTION_LENGTH];
    char answer[MAX_ANSWER_LENGTH];
    int choice;

    do {
        printf("\n1. Register\n2. Login\n3. Exit\nEnter your choice: ");
        scanf("%d", &choice);
        getchar(); // Consume newline character from previous input

        switch(choice) {
case 1:
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0'; // Remove trailing newline
    getchar(); // Consume newline character from input buffer

    printf("Enter password: ");
    fgets(password, sizeof(password), stdin);
    password[strcspn(password, "\n")] = '\0'; // Remove trailing newline
    getchar(); // Consume newline character from input buffer

    printf("Enter 6-digit MFA code: ");
    fgets(mfa_code, sizeof(mfa_code), stdin);
    mfa_code[strcspn(mfa_code, "\n")] = '\0'; // Remove trailing newline
    getchar(); // Consume newline character from input buffer

    printf("Enter a personal question: ");
    fgets(question, sizeof(question), stdin);
    question[strcspn(question, "\n")] = '\0'; // Remove trailing newline
    getchar(); // Consume newline character from input buffer

    printf("Enter the answer to the personal question: ");
    fgets(answer, sizeof(answer), stdin);
    answer[strcspn(answer, "\n")] = '\0'; // Remove trailing newline
    getchar(); // Consume newline character from input buffer

    register_user(username, password, mfa_code, question, answer);
    break;

            case 2:
                printf("Enter username: ");
                fgets(username, sizeof(username), stdin);
                username[strcspn(username, "\n")] = '\0'; // Remove trailing newline

                printf("Enter password: ");
                fgets(password, sizeof(password), stdin);
                password[strcspn(password, "\n")] = '\0'; // Remove trailing newline

                login(username, password);
                break;
            case 3:
                printf("Exiting...\n");
                break;
            default:
                printf("Invalid choice. Please try again.\n");
                break;
        }
    } while(choice != 3);

    return 0;
}

