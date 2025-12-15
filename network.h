#ifndef NETWORK_H
#define NETWORK_H

// Network initialization and cleanup
int init_network(void);
void cleanup_network(void);

// Packet transmission/reception
int send_packet_over_network(const char* packet, const char* ip, int port);
int receive_packet_over_network(char** packet, int port);

#endif // NETWORK_H
