#include "network.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#endif

// Network initialization
int init_network(void) {
#ifdef _WIN32
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        fprintf(stderr, "WSAStartup failed: %d\n", result);
        return -1;
    }
#endif
    return 0;
}

// Network cleanup
void cleanup_network(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Send packet over network (Sender - Server)
int send_packet_over_network(const char* packet, const char* ip, int port) {
#ifdef _WIN32
    SOCKET server_socket = INVALID_SOCKET, client_socket = INVALID_SOCKET;
    struct sockaddr_in server_addr = { 0 }, client_addr = { 0 };
    int client_addr_len = sizeof(client_addr);
#else
    int server_socket = -1, client_socket = -1;
    struct sockaddr_in server_addr = { 0 }, client_addr = { 0 };
    socklen_t client_addr_len = sizeof(client_addr);
#endif

    // Create socket
#ifdef _WIN32
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed\n");
        return -1;
    }
#else
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        return -1;
    }
#endif

    // Address reuse option
    int opt = 1;
#ifdef _WIN32
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
#else
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    // Set server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    if (ip == NULL || strcmp(ip, "") == 0) {
        server_addr.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces
    }
    else {
        // Use inet_pton (supported on Windows, macOS, Linux)
        if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
            // If inet_pton fails, try inet_addr (for backward compatibility)
            unsigned long addr = inet_addr(ip);
#ifdef _WIN32
            if (addr == INADDR_NONE || addr == INADDR_ANY) {
#else
            if (addr == (unsigned long)-1) {
#endif
                fprintf(stderr, "Invalid IP address: %s\n", ip);
#ifdef _WIN32
                closesocket(server_socket);
#else
                close(server_socket);
#endif
                return -1;
            }
            server_addr.sin_addr.s_addr = addr;
        }
    }
    server_addr.sin_port = htons(port);

    // Bind
#ifdef _WIN32
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Bind failed\n");
        closesocket(server_socket);
        return -1;
    }
#else
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        return -1;
    }
#endif

    // Listen
#ifdef _WIN32
    if (listen(server_socket, 1) == SOCKET_ERROR) {
        fprintf(stderr, "Listen failed\n");
        closesocket(server_socket);
        return -1;
    }
#else
    if (listen(server_socket, 1) < 0) {
        perror("Listen failed");
        close(server_socket);
        return -1;
    }
#endif

    printf("Server waiting... (Port: %d)\n", port);
    printf("Waiting for client connection...\n");

    // Wait for client connection
#ifdef _WIN32
    client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_socket == INVALID_SOCKET) {
        fprintf(stderr, "Accept failed\n");
        closesocket(server_socket);
        return -1;
    }
#else
    client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
    if (client_socket < 0) {
        perror("Accept failed");
        close(server_socket);
        return -1;
    }
#endif

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    printf("Client connected: %s\n", client_ip);

    // Send packet
    size_t packet_len = strlen(packet);
    size_t sent = 0;
    while (sent < packet_len) {
#ifdef _WIN32
        int result = send(client_socket, packet + sent, (int)(packet_len - sent), 0);
        if (result == SOCKET_ERROR) {
            fprintf(stderr, "Send failed\n");
            closesocket(client_socket);
            closesocket(server_socket);
            return -1;
        }
#else
        ssize_t result = send(client_socket, packet + sent, packet_len - sent, 0);
        if (result < 0) {
            perror("Send failed");
            close(client_socket);
            close(server_socket);
            return -1;
        }
#endif
        sent += result;
    }

    printf("Packet sent successfully (%zu bytes)\n", packet_len);

    // Close connection
#ifdef _WIN32
    closesocket(client_socket);
    closesocket(server_socket);
#else
    close(client_socket);
    close(server_socket);
#endif

    return 0;
}

// Receive packet from network (Receiver - Client)
int receive_packet_over_network(char** packet, int port) {
#ifdef _WIN32
    SOCKET client_socket;
    struct sockaddr_in server_addr;
#else
    int client_socket;
    struct sockaddr_in server_addr;
#endif

    // Create socket
#ifdef _WIN32
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        fprintf(stderr, "Socket creation failed\n");
        return -1;
    }
#else
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        perror("Socket creation failed");
        return -1;
    }
#endif

    // Enter server address
    char server_ip[256];
    printf("Enter sender IP address: ");
    if (fgets(server_ip, sizeof(server_ip), stdin) == NULL) {
        fprintf(stderr, "Failed to read IP address\n");
#ifdef _WIN32
        closesocket(client_socket);
#else
        close(client_socket);
#endif
        return -1;
    }
    // Remove newline character
    size_t len = strlen(server_ip);
    if (len > 0 && server_ip[len - 1] == '\n') {
        server_ip[len - 1] = '\0';
    }

    // Set server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address\n");
#ifdef _WIN32
        closesocket(client_socket);
#else
        close(client_socket);
#endif
        return -1;
    }

    printf("Connecting to server... (%s:%d)\n", server_ip, port);

    // Connect to server
#ifdef _WIN32
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        fprintf(stderr, "Connection failed\n");
        closesocket(client_socket);
        return -1;
    }
#else
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(client_socket);
        return -1;
    }
#endif

    printf("Connected to server\n");

    // Receive packet
    size_t capacity = 4096;
    *packet = (char*)malloc(capacity);
    if (!*packet) {
        fprintf(stderr, "Memory allocation failed\n");
#ifdef _WIN32
        closesocket(client_socket);
#else
        close(client_socket);
#endif
        return -1;
    }

    size_t received = 0;
    char buffer[1024];
    while (1) {
#ifdef _WIN32
        int result = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (result == SOCKET_ERROR) {
            fprintf(stderr, "Receive failed\n");
            free(*packet);
            closesocket(client_socket);
            return -1;
        }
        if (result == 0) {
            break;  // Close connection
        }
#else
        ssize_t result = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        if (result < 0) {
            perror("Receive failed");
            free(*packet);
            close(client_socket);
            return -1;
        }
        if (result == 0) {
            break;  // Close connection
        }
#endif

        buffer[result] = '\0';

        // Expand buffer
        if (received + result >= capacity) {
            capacity *= 2;
            char* new_packet = (char*)realloc(*packet, capacity);
            if (!new_packet) {
                fprintf(stderr, "Memory reallocation failed\n");
                free(*packet);
#ifdef _WIN32
                closesocket(client_socket);
#else
                close(client_socket);
#endif
                return -1;
            }
            *packet = new_packet;
        }

        memcpy(*packet + received, buffer, result);
        received += result;
    }

    (*packet)[received] = '\0';
    printf("Packet received successfully (%zu bytes)\n", received);

    // Close connection
#ifdef _WIN32
    closesocket(client_socket);
#else
    close(client_socket);
#endif

    return 0;
}
