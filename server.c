#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include <openssl/rsa.h>

// Maximum number of clients that can be connected at the same time
#define MAX_CLIENTS 10

// Maximum size of the buffer for incoming messages
#define BUFFER_SIZE 4096

// Maximum length of a client's name
#define NAME_LEN 32

// Constants for ANSI color codes
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_RESET "\x1b[0m"

// Global variables

int port = 8080;
int priv_port = 8081;

// Number of currently connected clients
static unsigned int connected_clients_count = 0;

// Unique identifier for each client
static int uid = 10;

// Color structure
typedef struct {
    char *name;
    char *value;
} color_t;

color_t colors[] = {
        {"red",     ANSI_COLOR_RED},
        {"green",   ANSI_COLOR_GREEN},
        {"yellow",  ANSI_COLOR_YELLOW},
        {"blue",    ANSI_COLOR_BLUE},
        {"magenta", ANSI_COLOR_MAGENTA},
        {"cyan",    ANSI_COLOR_CYAN},
        {"reset",   ANSI_COLOR_RESET}
};


// Client structure
typedef struct {
    int sockfd;  // Socket descriptor for the client connection
    int priv_sockfd;  // Socket descriptor for the server-client exclusive cominication
    struct sockaddr_in addr; // Structure describing the Internet socket address of the client
    int uid;     // Unique identifier for the client
    char name[NAME_LEN];  // Name of the client
    color_t color; // Color for the client
    RSA *public_key;  // Client's public key
} client_t;

// Array of pointers to connected clients
client_t *connected_clients[MAX_CLIENTS];

// Mutex for accessing the connected_clients array
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;


// Functions

/**
 * Create a socket and bind it to the specified hostname and port.
 *
 * @param port Pointer to the port number to bind the socket to. If the port is 0, a random available port will be chosen.
 * @return The socket descriptor for the newly created socket.
 * @throws An error if the socket could not be created or bound.
 */
int create_socket(int *port) {
    int sockfd;
    struct sockaddr_in server_addr;

    // Create the socket
    sockfd = socket(PF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[" ANSI_COLOR_RED "-" ANSI_COLOR_RESET "]" ANSI_COLOR_RED "ERROR:" ANSI_COLOR_RESET " Socket creation error...\n");
        exit(EXIT_FAILURE);
    }

    printf("[" ANSI_COLOR_GREEN "+" ANSI_COLOR_RESET "] TCP server socket created\n");

    // Set the address and port for the socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = PF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(*port);

    // Bind the socket to the address and port
    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("[" ANSI_COLOR_RED "-" ANSI_COLOR_RESET "] " ANSI_COLOR_RED "ERROR:" ANSI_COLOR_RESET " bind...\n");
        exit(EXIT_FAILURE);
    }

    printf("[" ANSI_COLOR_GREEN "+" ANSI_COLOR_RESET "] TCP server socket bind success\n");

    // If the port was set to 0, get the actual port that was chosen
    if (*port == 0) {
        socklen_t server_len = sizeof(server_addr);
        if (getsockname(sockfd, (struct sockaddr *) &server_addr, &server_len) < 0) {
            perror("getsockname");
            exit(EXIT_FAILURE);
        }
        *port = ntohs(server_addr.sin_port);
    }

    return sockfd;
}

/**
 * Remove newline characters from a string.
 *
 * @param str The string to clean.
 *
 * @param length The length of the string.
 */
void clean_string(char *str, int length) {
    int i;
    for (i = 0; i < length; i++) {
        if (str[i] == '\n' || str[i] == '\r') {
            str[i] = '\0';
        }
    }
}

/**
 * Check if a string is a command (starts with '/').
 *
 * @param str The string to check.
 * @return 1 if the string is a command, 0 otherwise.
 */
int is_command(char *str) {
    return str[0] == '/';
}

/**
 * Check if a name is already in use by another client.
 *
 * @param name The name to check.
 * @return 1 if the name is already in use, 0 otherwise.
 */
int is_name_in_use(char *name) {
    // Lock the mutex to access the connected_clients array
    pthread_mutex_lock(&clients_mutex);

    for (int i = 0; i < connected_clients_count; i++) {
        if (strcmp(connected_clients[i]->name, name) == 0) {
            // Name is in use, unlock the mutex and return 1
            pthread_mutex_unlock(&clients_mutex);
            return 1;
        }
    }

    // Name is not in use, unlock the mutex and return 0
    pthread_mutex_unlock(&clients_mutex);
    return 0;
}

/**
 * Check if a string has spaces.
 *
 * @param str The string to check.
 *
 * @return 1 if the string has spaces, 0 otherwise.
 */
int has_spaces(char* str) {
    for (int i = 0; i < strlen(str); i++) {
        if (str[i] == ' ') {
            return 1;
        }
    }
    return 0;
}


/**
 * Add a client to the connected_clients array.
 *
 * @param client The client to add.
 */
void add_client(client_t *client) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connected_clients[i] == NULL) {
            connected_clients[i] = client;
            connected_clients_count++;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

/**
 * Remove a client from the connected_clients array.
 *
 * @param uid The unique identifier of the client to remove.
 */
void remove_client(int uid) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connected_clients[i] != NULL) {
            if (connected_clients[i]->uid == uid) {
                connected_clients[i] = NULL;
                connected_clients_count--;
                break;
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}


/**
 * Function to receive and store the client's public key
 *
 * @param client The client to receive the public key from.
 * @return 0 if the public key was received successfully, -1 otherwise.
 */
int receive_client_key(client_t *client) {
    // Receive the size of the public key
    int key_size;
    if (recv(client->sockfd, &key_size, sizeof(key_size), 0) < 0) {
        printf("Error receiving size of RSA public key.\n");
        return -1;
    }

    // Allocate memory for the public key
    unsigned char *key_buffer = (unsigned char *) malloc(key_size);
    if (key_buffer == NULL) {
        printf("Error allocating memory for RSA public key.\n");
        return -1;
    }

    // Receive the public key
    if (recv(client->sockfd, key_buffer, key_size, 0) < 0) {
        printf("Error receiving RSA public key.\n");
        free(key_buffer);
        return -1;
    }

// Convert the DER-encoded buffer to an RSA public key
    const unsigned char *temp = key_buffer;
    client->public_key = d2i_RSAPublicKey(NULL, &temp, key_size);
    if (client->public_key == NULL) {
        printf("Error converting RSA public key from DER-encoded buffer.\n");
        return -1;
    }

// Free the memory allocated for the public key
    free(key_buffer);
    return 0;
}

/**
 * Send a message to all connected clients.
 *
 * @param msg The message to send.
 * @param sender_uid The unique identifier of the client who sent the message.
 * @param sys_msg Whether is the server who sent the message [1 or 0].
 */
void send_message(char *msg, int sender_uid, int sys_msg) {
    // Lock the clients mutex
    pthread_mutex_lock(&clients_mutex);

    client_t *sender = NULL;
    if (!sys_msg) {
        // Find the client who sent the message
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (connected_clients[i] != NULL && connected_clients[i]->uid == sender_uid) {
                sender = connected_clients[i];
                break;
            }
        }
    }

    // Send the message to all connected clients
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!sys_msg) {
            if (connected_clients[i] != NULL && connected_clients[i]->uid != sender->uid &&
                strcmp(connected_clients[i]->name, "Anonymous") != 0) {
                char buffer[BUFFER_SIZE];
                sprintf(buffer, "[broadcast] %s<%s>%s %s\n", sender->color.value, sender->name, ANSI_COLOR_RESET, msg);
                send(connected_clients[i]->sockfd, buffer, strlen(buffer), 0);
            }
        } else {
            if (connected_clients[i] != NULL && strcmp(connected_clients[i]->name, "Anonymous") != 0) {
                send(connected_clients[i]->sockfd, msg, strlen(msg), 0);
            }
        }
    }
    // Unlock the clients mutex
    pthread_mutex_unlock(&clients_mutex);

    memset(msg, 0, BUFFER_SIZE);
}


/**
 * Executes the '/list' command, which lists all connected clients.
 *
 * @param client The client that issued the command.
 */
void execute_list_command(client_t *client) {
    char buffer[BUFFER_SIZE];

    sprintf(buffer, "--- Connected clients ---\n");
    if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
        perror("send");
    }

    int i;
    for (i = 0; i < MAX_CLIENTS; i++) {
        if (connected_clients[i] != NULL && strcmp(connected_clients[i]->name, "Anonymous") != 0) {
            if (connected_clients[i]->uid == client->uid) {
                sprintf(buffer, "%s%s%s (you)\n", connected_clients[i]->color.value, connected_clients[i]->name,
                        ANSI_COLOR_RESET);
            } else {
                sprintf(buffer, "%s%s%s\n", connected_clients[i]->color.value, connected_clients[i]->name,
                        ANSI_COLOR_RESET);
            }
            if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
                perror("send");
            }
        }
    }
}

/**
 * Executes the '/exit' command, which disconnects the client from the server.
 *
 * @param client The client that issued the command.
 */
void execute_exit_command(client_t *client) {
    char buffer[BUFFER_SIZE];
    sprintf(buffer, "[system] %s%s%s has " ANSI_COLOR_RED "left " ANSI_COLOR_RESET "the chat.\n", client->color.value,
            client->name, ANSI_COLOR_RESET);
    send_message(buffer, client->uid, 1);
}

/**
 * Executes the '/key' command, which sends a client's public key to another client.
 *
 * @param client The client that issued the command.
 * @param buffer The full command.
 */
void execute_key_command(client_t *client, char *buffer) {
    char *recipient_name;

    // Split the buffer to get the client's recipient_name
    recipient_name = strtok(buffer + strlen("/key"), " ");

    char message[BUFFER_SIZE];

    if (recipient_name == NULL) {
        // If the recipient_name was not found, send an error message to the sender
        sprintf(message, "[system] %sError: Invalid command. %s\n", ANSI_COLOR_RED, ANSI_COLOR_RESET);
        send(client->sockfd, message, strlen(message), 0);
        return;
    }

    // Lock the clients mutex
    pthread_mutex_lock(&clients_mutex);

    // Find the recipient's client structure
    client_t *recipient = NULL;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connected_clients[i] != NULL && strcmp(connected_clients[i]->name, recipient_name) == 0) {
            recipient = connected_clients[i];
            break;
        }
    }

    // Unlock the clients mutex
    pthread_mutex_unlock(&clients_mutex);

    // If the recipient was found, send the public key
    if (recipient != NULL) {
        // Get the size of the public key
        int key_size = i2d_RSAPublicKey(recipient->public_key, NULL);
        if (key_size < 0) {
            printf("Error getting size of RSA public key.\n");
            return;
        }

        // Allocate memory for the public key
        unsigned char *key_buffer = (unsigned char *) malloc(key_size);
        if (key_buffer == NULL) {
            printf("Error allocating memory for RSA public key.\n");
            return;
        }

        // Convert the public key to a DER-encoded buffer
        unsigned char *temp = key_buffer;
        i2d_RSAPublicKey(recipient->public_key, &temp);

        // Send the size of the public key to the client
        if (send(client->priv_sockfd, &key_size, sizeof(key_size), 0) < 0) {
            printf("Error sending size of RSA public key.\n");
            free(key_buffer);
            return;
        }

        // Send the public key to the client
        if (send(client->priv_sockfd, key_buffer, key_size, 0) < 0) {
            printf("Error sending RSA public key.\n");
            free(key_buffer);
            return;
        }

        // Free the memory allocated for the public key
        free(key_buffer);
    } else {
        // If the recipient was not found, send an error message to the sender
        sprintf(message, "[system] %sError: Client '%s' not found. %s\n",
                ANSI_COLOR_RED, recipient_name, ANSI_COLOR_RESET);
        send(client->sockfd, message, strlen(message), 0);
    }

}

/**
 * Executes the '/private' command, which sends a private message to another client.
 *
 * @param client The client who sent the command.
 * @param buffer The full command and message.
 */
void execute_private_command(client_t *client, char *buffer) {
    char *receiver_name;
    char *b64string;
    char *message_size;
    char *b64string_size;

    char *saveptr;

    // Split the buffer into the receiver's name and the message
    receiver_name = strtok_r(buffer + strlen("/private"), " ", &saveptr);
    message_size = strtok_r(NULL, " ", &saveptr);
    b64string_size = strtok_r(NULL, " ", &saveptr);
    b64string = strtok_r(NULL, "", &saveptr);

    // Lock the clients mutex
    pthread_mutex_lock(&clients_mutex);

    // Find the receiver's client structure
    client_t *receiver = NULL;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connected_clients[i] != NULL && strcmp(connected_clients[i]->name, receiver_name) == 0) {
            receiver = connected_clients[i];
            break;
        }
    }

    // If the receiver was found, send the private message
    if (receiver != NULL) {
        char message_buffer[BUFFER_SIZE];
        memset(message_buffer, 0, BUFFER_SIZE);
        sprintf(message_buffer, "[private] %s<%s>%s %d %d ", client->color.value, client->name, ANSI_COLOR_RESET, atoi(message_size), atoi(b64string_size));
        memcpy(message_buffer + strlen(message_buffer), b64string, atoi(b64string_size));
        send(receiver->sockfd, message_buffer, strlen(message_buffer), 0);
    } else {
        // If the receiver was not found, send an error message to the sender
        char message_buffer[BUFFER_SIZE];
        sprintf(message_buffer, "[system] " ANSI_COLOR_RED "Error: Client '%s' not found. " ANSI_COLOR_RESET "\n",
                receiver_name);
        send(client->sockfd, message_buffer, strlen(message_buffer), 0);
    }

    // Unlock the clients mutex
    pthread_mutex_unlock(&clients_mutex);
}

/**
 * Executes the '/help' command, which displays a list of available commands.
 *
 * @param client The client that issued the command.
 */
void execute_help_command(client_t *client) {
    char buffer[BUFFER_SIZE];

    sprintf(buffer, "--- Available commands ---\n");
    if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
        perror("send");
    }

    sprintf(buffer, "/list - List all connected clients\n");
    if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
        perror("send");
    }

    sprintf(buffer, "/exit - Disconnect from the server\n");
    if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
        perror("send");
    }

    sprintf(buffer, "/private [client] [message] - Send a private message to another client\n");
    if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
        perror("send");
    }

    sprintf(buffer, "/help - Display this list of commands\n");
    if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
        perror("send");
    }
}

/**
 * Thread function for handling a single client.
 *
 * @param arg Pointer to the client structure for the client to be handled.
 */
void *handle_client(void *arg) {
    char buffer[BUFFER_SIZE];
    char name[NAME_LEN];
    memset(name, 0, NAME_LEN);
    memset(buffer, 0, BUFFER_SIZE);

    client_t *client = (client_t *) arg;

    // Receive the client's public key
    if (receive_client_key(client) < 0){
        perror("[" ANSI_COLOR_RED "-" ANSI_COLOR_RESET "] Error: Cannot receive client key.");
        return NULL;
    }

    // Send a message to the client requesting their name
    sprintf(buffer, "[system] Welcome to the chat. Please enter your name: ");
    if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
        perror("send");
        return NULL;
    }

    // Read the client's name
    if (recv(client->sockfd, name, NAME_LEN, 0) < 0) {
        perror("recv");
        return NULL;
    }

    // Remove newline characters from the name
    clean_string(name, NAME_LEN);

    memset(buffer, 0, BUFFER_SIZE);

    has_spaces(name);

    // Validate the client's name
    while (strlen(name) == 0 || strlen(name) > NAME_LEN || is_name_in_use(name) || has_spaces(name)) {
        // Send an error message if the name is invalid
        if (strlen(name) == 0 || strlen(name) > NAME_LEN) {
            sprintf(buffer, "%s[system] Error: Enter the name correctly (between 1 and %d characters): %s",
                    ANSI_COLOR_RED, NAME_LEN, ANSI_COLOR_RESET);
        } else if (is_name_in_use(name)) {
            sprintf(buffer, "%s[system] Error: That name is already in use. Please choose another one: %s",
                    ANSI_COLOR_RED, ANSI_COLOR_RESET);
        } else if (has_spaces(name)) {
            sprintf(buffer, "%s[system] Error: The name cannot have spaces. Please choose another one: %s",
                    ANSI_COLOR_RED, ANSI_COLOR_RESET);
        }

        if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
            perror("send");
            return NULL;
        }

        memset(name, 0, NAME_LEN);

        // Read the client's name again
        if (recv(client->sockfd, name, NAME_LEN, 0) < 0) {
            perror("recv");
            return NULL;
        }

        // Remove newline characters from the name
        clean_string(name, NAME_LEN);

        memset(buffer, 0, BUFFER_SIZE);
    }

    // Send flag to client to validate that they have accessed the chat and can continue
    sprintf(buffer, "access_successfully");
    if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
        perror("send");
        return NULL;
    }

    // Wait for the client to be ready to receive the next message
    sleep(1);

    // Update the client's name
    memset(client->name, 0, NAME_LEN);
    strcpy(client->name, name);

    memset(buffer, 0, BUFFER_SIZE);

    sprintf(buffer, "[system] Welcome to the chat %s%s%s. Use /help to see the available commands.\n",
            client->color.value, client->name, ANSI_COLOR_RESET);
    if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
        perror("send");
        return NULL;
    }

    memset(buffer, 0, BUFFER_SIZE);

    // Send a message to all connected clients announcing the new client's name
    sprintf(buffer, "[system] %s%s%s has " ANSI_COLOR_GREEN "joined " ANSI_COLOR_RESET "the chat.\n",
            client->color.value, client->name, ANSI_COLOR_RESET);
    send_message(buffer, client->uid, 1);

    // Send a message to new client announcing the connected clients names
    sprintf(buffer, "[system] Connected clients: ");
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (connected_clients[i] != NULL && strcmp(connected_clients[i]->name, "Anonymous") != 0) {
            if (connected_clients[i]->uid == client->uid) {
                strcat(buffer, connected_clients[i]->name);
                strcat(buffer, " (you)");
            } else {
                strcat(buffer, connected_clients[i]->name);
            }
            strcat(buffer, ", ");
        }
    }
    buffer[strlen(buffer) - 2] = '\0';
    strcat(buffer, "\n");

    if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
        perror("send");
        return NULL;
    }

    memset(buffer, 0, BUFFER_SIZE);

    // Loop to receive and handle messages from the client
    while (1) {
        // Read a message from the client
        int bytes_received = recv(client->sockfd, buffer, BUFFER_SIZE, 0);

        if (bytes_received < 0) {
            // An error occurred
            perror("recv");
            execute_exit_command(client);
            break;
        } else if (bytes_received == 0) {
            // The connection was closed by the client
            execute_exit_command(client);
            break;
        }

        // Check if the message is a command
        if (is_command(buffer)) {
            // Execute the command
            if (strncmp(buffer, "/list", 5) == 0) {
                execute_list_command(client);
            } else if (strncmp(buffer, "/exit", 5) == 0) {
                execute_exit_command(client);
                break;
            } else if (strncmp(buffer, "/private", 8) == 0) {
                execute_private_command(client, buffer);
            } else if (strncmp(buffer, "/help", 5) == 0) {
                execute_help_command(client);
            } else if (strncmp(buffer, "/key", 4) == 0) {
                execute_key_command(client, buffer);
            } else {
                sprintf(buffer, "[system] " ANSI_COLOR_RED "Error: Invalid command. " ANSI_COLOR_RESET "\n");
                if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
                    perror("send");
                }
            }
        } else {
            if (strlen(buffer) < 1) {
                sprintf(buffer,
                        "[system] " ANSI_COLOR_RED "Error: The message must have at least 1 character. " ANSI_COLOR_RESET "\n");
                if (send(client->sockfd, buffer, strlen(buffer), 0) < 0) {
                    perror("send");
                }
            } else {
                // Send the message to all connected clients
                send_message(buffer, client->uid, 0);
            }
        }
        memset(buffer, 0, BUFFER_SIZE);
    }

    // Print disconnection message
    printf("[" ANSI_COLOR_MAGENTA "*" ANSI_COLOR_RESET "] Client" ANSI_COLOR_RED " disconnected" ANSI_COLOR_RESET " from %s%s:%d%s.\n",
           client->color.value, inet_ntoa(client->addr.sin_addr), ntohs(client->addr.sin_port), ANSI_COLOR_RESET);


    // Close the client's socket
    close(client->sockfd);

    // Remove the client from the connected_clients array
    remove_client(client->uid);

    // Free the memory allocated for the client structure
    free(client);

    return NULL;
}

/**
 * Handle the broken pipe signal.
 *
 * @param signal The signal number.
 */
void sigpipe_handler(int signal) {
    printf("[" ANSI_COLOR_MAGENTA "*" ANSI_COLOR_RESET "] Broken pipe signal received. Ignoring it.\n");
}


int main(int argc, char *argv[]) {
    int sockfd;
    int client_sockfd;
    struct sockaddr_in client_addr;
    socklen_t client_len;
    pthread_t new_thread;

    if (argc != 2) {
        printf(ANSI_COLOR_GREEN "Usage:" ANSI_COLOR_BLUE "%s" ANSI_COLOR_CYAN " <port>" ANSI_COLOR_RESET "\n", argv[0]);
        return EXIT_FAILURE;
    }

    //  Get the command-line port
    port = atoi(argv[1]);
    priv_port = port + 1;

    // Create a socket and bind it to the specified hostname and port
    sockfd = create_socket(&port);

    // Listen for connections
    listen(sockfd, MAX_CLIENTS);

    // Print listening message
    printf("[" ANSI_COLOR_GREEN "+" ANSI_COLOR_RESET "] TCP server listening on port %d\n", port);

    // Ignore the SIGPIPE signal which occurs when the client closes the connection unexpectedly
    signal(SIGPIPE, sigpipe_handler);

    char buffer[BUFFER_SIZE];
    memset(buffer, 0, BUFFER_SIZE);

    // Create a new socket for exclusive client communication
    int priv_sockfd = create_socket(&priv_port);

    listen(priv_sockfd, MAX_CLIENTS);

    // Print listening message
    printf("[" ANSI_COLOR_GREEN "+" ANSI_COLOR_RESET "] TCP server listening on port %d\n", priv_port);


    // Loop to accept new connections
    while (1) {
        client_len = sizeof(client_addr);
        if ((client_sockfd = accept(sockfd, (struct sockaddr *) &client_addr, &client_len)) < 0) {
            perror("[" ANSI_COLOR_RED "-" ANSI_COLOR_RESET "] " ANSI_COLOR_RED "ERROR:" ANSI_COLOR_RESET " accept...\n");
        }

        // Check if the maximum number of clients has been reached
        if (connected_clients_count == MAX_CLIENTS) {
            sprintf(buffer, "[system] " ANSI_COLOR_RED "Error: The server is full." ANSI_COLOR_RESET "\n");
            if (send(client_sockfd, buffer, BUFFER_SIZE, 0) < 0) {
                perror("send");
            }
            close(client_sockfd);
        } else {
            // Accept client connection in private socket
            int client_priv_sockfd;
            if ((client_priv_sockfd = accept(priv_sockfd, (struct sockaddr *) &client_addr, &client_len)) < 0) {
                perror("[" ANSI_COLOR_RED "-" ANSI_COLOR_RESET "] " ANSI_COLOR_RED "ERROR:" ANSI_COLOR_RESET " accept...\n");
            }

            // Create a new client structure for the new connection
            client_t *new_client = (client_t *) malloc(sizeof(client_t));
            new_client->sockfd = client_sockfd;
            new_client->priv_sockfd = client_priv_sockfd;
            new_client->uid = uid++;
            new_client->color = colors[connected_clients_count % 6];
            new_client->addr = client_addr;
            // Temporal client's name
            strcpy(new_client->name, "Anonymous");

            // Add the new client to the connected_clients array
            add_client(new_client);

            // Print connection message
            printf("[" ANSI_COLOR_MAGENTA "*" ANSI_COLOR_RESET "] Client" ANSI_COLOR_GREEN " connected" ANSI_COLOR_RESET " from %s%s:%d%s.\n",
                   new_client->color.value, inet_ntoa(new_client->addr.sin_addr), ntohs(new_client->addr.sin_port),
                   ANSI_COLOR_RESET);

            // Create a new thread for the new client
            if (pthread_create(&new_thread, NULL, handle_client, (void *) new_client) != 0) {
                perror("pthread_create");
            }


        }
    }

    close(sockfd);

    return 0;
}


