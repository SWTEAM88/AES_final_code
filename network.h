#ifndef NETWORK_H
#define NETWORK_H

// �ㅽ듃�뚰겕 珥덇린�� 諛� �뺣━
int init_network(void);
void cleanup_network(void);

// �⑦궥 �≪닔��
int send_packet_over_network(const char* packet, const char* ip, int port);
int receive_packet_over_network(char** packet, int port);

#endif // NETWORK_H
