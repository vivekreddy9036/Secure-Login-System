#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <termios.h>
#include <unistd.h>

#define MAX_USERS 10
#define USERNAME_LENGTH 20
#define MAX_PASSWORD_LENGTH 64  // Maximum allowed password length
#define PASSWORD_LENGTH (SHA256_DIGEST_LENGTH * 2) // Twice the length of SHA256 hash in hexadecimal
#define MAX_LOGIN_ATTEMPTS 3
#define MAX_QUESTION_LENGTH 100
#define MAX_ANSWER_LENGTH 50

struct termios old, new;

/* Initialize new terminal i/o settings */
void initTermios(int echo) {
    tcgetattr(0, &old); /* grab old terminal i/o settings */
    new = old; /* make new settings same as old settings */
    new.c_lflag &= ~ICANON; /* disable buffered i/o */
    new.c_lflag &= echo ? ECHO : ~ECHO; /* set echo mode */
    tcsetattr(0, TCSANOW, &new); /* apply terminal io settings */
}

/* Restore old terminal i/o settings */
void resetTermios(void) {
    tcsetattr(0, TCSANOW, &old);
}

/* Read 1 character - echo defines echo mode */
char getch_(int echo) {
    char ch;
    initTermios(echo);
    ch = getchar();
    resetTermios();
    return ch;
}

/* Read 1 character without echo */
char getch(void) {
    return getch_(0);
}

/* Read 1 character with echo */
char getche(void) {
    return getch_(1);
}

typedef struct {
    char username[USERNAME_LENGTH];
    char password[PASSWORD_LENGTH + 1]; // Additional space for null terminator
    char mfa_code[7]; // Six-digit MFA code + null terminator
    char personal_question[MAX_QUESTION_LENGTH];
    char personal_answer[MAX_ANSWER_LENGTH];
} User;

User users[MAX_USERS];
int num_users = 0;

void register_user(const char *username, const char *password, const char *mfa_code, const char *question, const char *answer) {
    if (num_users >= MAX_USERS) {
        printf("Maximum number of users reached.\n");
        return;
    }

    if (strlen(username) >= USERNAME_LENGTH || strlen(password) >= PASSWORD_LENGTH || strlen(mfa_code) != 6 || strlen(question) >= MAX_QUESTION_LENGTH || strlen(answer) >= MAX_ANSWER_LENGTH) {
        printf("Invalid input.\n");
        return;
    }

    strcpy(users[num_users].username, username);
    strcpy(users[num_users].password, password);
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
                if (strcmp(users[i].password, password) == 0) {
                    // Prompt for MFA code
                    char mfa_input[7];
                    printf("Enter your 6-digit MFA code: ");
                    for (int k = 0; k < 6; k++) {
                        mfa_input[k] = getch();
                        printf("*");
                    }
                    mfa_input[6] = '\0';
                    printf("\n");

                    // Compare MFA code
                    if (strcmp(users[i].mfa_code, mfa_input) == 0) {
                        // Ask personal question
                        char answer[MAX_ANSWER_LENGTH];
                        printf("%s\n", users[i].personal_question);
                        printf("Enter your answer: ");
                        scanf("%s", answer);

                        // Compare personal answer
                        if (strcmp(users[i].personal_answer, answer) == 0) {
                            printf("Login successful.\n");
                            return 1;
                        } else {
                            printf("Incorrect answer to personal question.\n");
                            attempts_left--;
                            if (attempts_left > 0) {
                                printf("Attempts left: %d\n", attempts_left);
                                printf("Please try again.\n");
                            } else {
                                printf("Max login attempts reached. Account locked.\n");
                                return 0;
                            }
                        }
                    } else {
                        printf("Incorrect MFA code.\n");
                        attempts_left--;
                        if (attempts_left > 0) {
                            printf("Attempts left: %d\n", attempts_left);
                            printf("Please try again.\n");
                        } else {
                            printf("Max login attempts reached. Account locked.\n");
                            return 0;
                        }
                    }
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
    char password[MAX_PASSWORD_LENGTH + 1]; // Additional space for null terminator
    char mfa_code[7];
    char question[MAX_QUESTION_LENGTH];
    char answer[MAX_ANSWER_LENGTH];
    int choice;

    do {
        printf("\n1. Register\n2. Login\n3. Exit\nEnter your choice: ");
        scanf("%d", &choice);

        switch(choice) {
            case 1:
                printf("Enter username: ");
                scanf("%s", username);
                int password_length;
                do {
                    printf("Enter password length (max %d): ", MAX
                    scanf("%d", &password_length);
                    if (password_length <= 0 || password_length > MAX_PASSWORD_LENGTH) {
                        printf("Invalid password length. Please choose a length between 1 and %d.\n", MAX_PASSWORD_LENGTH);
                    }
                } while (password_length <= 0 || password_length > MAX_PASSWORD_LENGTH);

                printf("Enter password: ");
                for (int i = 0; i < password_length; i++) {
                    password[i] = getch();
                    printf("*");
                }
                password[password_length] = '\0'; // Null-terminate the password
                printf("\nEnter 6-digit MFA code: ");
                scanf("%s", mfa_code);
                printf("Enter a personal question: ");
                scanf(" %[^\n]s", question);
                printf("Enter the answer to the personal question: ");
                scanf(" %[^\n]s", answer);
                register_user(username, password, mfa_code, question, answer);
                break;
            case 2:
                printf("Enter username: ");
                scanf("%s", username);
                printf("Enter password: ");
                scanf("%s", password);
                printf("\n");
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

