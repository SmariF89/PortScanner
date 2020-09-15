#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <vector>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <netinet/ip.h> 
#include <netinet/tcp.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include <iomanip>    
#include <arpa/inet.h>
using namespace std;

struct ip_header {
    unsigned char ip_hl:4, ip_v:4; // hl = header length, v = version
    unsigned char ip_tos;       //Type of service
    unsigned short int ip_len;  //total length
    unsigned short int ip_id;   // identification
    unsigned short int ip_off;  // fragment offset
    unsigned char ip_ttl;       // time to live
    unsigned char ip_p;         // protocol
    unsigned short int ip_sum;  // checksum
    unsigned int ip_src;        // source ip address
    unsigned int ip_dst;        // destination ip address
};

struct tcp_header {
    unsigned short int th_sport;  //Source port
    unsigned short int th_dport;  // destination port
    unsigned int th_seq;          // sequence number
    unsigned int th_ack;          // acknowledge number
    unsigned char th_x2:4, th_off:4;  // data offset
    unsigned char th_flags;           //flags
    unsigned short int th_win;     //window
    unsigned short int th_sum;     // checksum
    unsigned short int th_urp;     // urgent pointer
};

const int minimumWait = 500000;

void error(const char *msg);
bool portIsIllegal(int port);
bool fillVectorFromFileAndShuffle(vector<int> &vec, string fileName);
void printReport(vector<int> &vec, int closed);
void printScanStatus(int i, vector<int> ports);
int randomWait();
unsigned short csum(unsigned short *buffer, int wordCount);
void fillIpHeader(struct ip_header * iph, struct sockaddr_in sin);
void fillTcpHeader(struct tcp_header *tcph, struct sockaddr_in sin);
void setTcpFlags(int flag, struct tcp_header *tcph);
int getHostByName(int argc, char *argv[]);

void TCPscan(vector<int> ports, vector<int> openPorts, int closed, int sockfd, struct sockaddr_in serverAddress);
void UDPscan(vector<int> ports, vector<int> openPorts, int closed, int sockfd, struct sockaddr_in serverAddress);
void FINscan(vector<int> ports, vector<int> openPorts, int closed, int sockfd, int argc, char *argv[]);
void SYNscan(vector<int> ports, vector<int> openPorts, int closed, int sockfd, struct sockaddr_in serverAddress);


int main(int argc, char *argv[])
{
    string scanningMethod = argv[3];

    vector<int> ports, openPorts;
    int closed = 0, sockfd;
    struct sockaddr_in serverAddress;

    // Set up server.
    struct hostent *server = gethostbyname(argv[1]);
    if(server == NULL) { error("ERROR, no such host"); }

    // Fetch ports from file.
    if(!fillVectorFromFileAndShuffle(ports, argv[2])) { error("ERROR, opening file"); }

    // Set up concerning the server address.
    bzero((char *) &serverAddress, sizeof(serverAddress));
    serverAddress.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serverAddress.sin_addr.s_addr, server->h_length);
    
    // Different scan methods. If
    if(scanningMethod == "TCP") { TCPscan(ports, openPorts, closed, sockfd, serverAddress); }
    else if(scanningMethod == "UDP") { UDPscan(ports, openPorts, closed, sockfd, serverAddress); }
    else if(scanningMethod == "FIN") { FINscan(ports, openPorts, closed, sockfd, argc, argv); }
    else if(scanningMethod == "SYN") { SYNscan(ports, openPorts, closed, sockfd, serverAddress); }
    else { cout << "No valid protocols input, terminating.." << endl; }

    close(sockfd);
    
    return 0;
}

void error(const char *msg) {
    perror(msg);
    exit(0);
}

bool portIsIllegal(int port) {
    return port == 22 || port == 80 || port == 443;
}

bool fillVectorFromFileAndShuffle(vector<int> &ports, string fileName) {
    ifstream iFile;
    iFile.open(fileName);
    char output[100];
    if(iFile.is_open()){
        while (!iFile.eof()) { 
            iFile >> output;
            ports.push_back(atoi(output));
        }
    }
    else { return false; }

    random_shuffle(ports.begin(), ports.end());
    iFile.close();
    return true;
}

void printReport(vector<int> &openPorts, int closed) {
    cout << "---------------------------------" << endl;
    cout << "Number of open ports: " << openPorts.size() << endl;
    cout << "Number of closed ports: " << closed << endl;
    cout << "Open ports: ";
    for(size_t i = 0; i < openPorts.size(); i++) {
        cout << openPorts[i]; 
        if(i < openPorts.size() - 1) { cout << ", "; } 
    }
    cout << endl;
}

void printScanStatus(int i, vector<int> ports) {
    cout << "Scan status:" << " about "<< fixed << setprecision(2) 
    << (i/(double)ports.size()) * 100 << "% done." << endl;
}

// The random added time is 0 - 0.5 second.
int randomWait() {
    srand(time(NULL));
    return (rand() % 500001);
}

void TCPscan(vector<int> ports, vector<int> openPorts, int closed, int sockfd, struct sockaddr_in serverAddress) {
    // Create the socket for TCP. 
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if(sockfd < 0) { error("ERROR opening socket"); } 

    // All ports are scanned with TCP protocol.
    // If connection fails, it means the triple handshake did not go through, and the port 
    // is assumed to be closed. Else the connecion was successful and port is assumed to be open.
    for(size_t i = 0; i < ports.size(); i++) {
        if(portIsIllegal(ports[i])) { continue; }

        serverAddress.sin_port = htons(ports[i]);
        if(connect(sockfd, (struct sockaddr *) &serverAddress, sizeof(serverAddress)) < 0) { closed++; } 
        else { openPorts.push_back(ports[i]); }
        
        // Wait for 0.5 sec plus some random time and print status of scan.
         if(ports.size() > 1) { usleep(500000 + randomWait()); }
        if(i % 2 == 0) { printScanStatus(i, ports); }
    }
    printReport(openPorts, closed);
}

void UDPscan(vector<int> ports, vector<int> openPorts, int closed, int sockfd, struct sockaddr_in serverAddress) {
    int rsockfd;

    // A buffer containing the message to be sent to the server.
    char bufferMessage[256];
    char rBufferMessage[65536];
    strcpy(bufferMessage, "hello world!");

    // Create the socket for UDP protocol. 
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockfd < 0) { error("ERROR opening socket"); }

    // Set up concerning the recieving server address.
    struct sockaddr_in r_serverAddress;
    memset(&r_serverAddress, 0, sizeof(r_serverAddress));
    r_serverAddress.sin_family = AF_INET;

    // Create a socket to try to recieve ICMP packet from server.
    rsockfd = socket(AF_INET, SOCK_RAW|SOCK_NONBLOCK, IPPROTO_ICMP);
    if(rsockfd < 0) { error("ERROR opening socket"); }

    // All ports are scanned with UDP protocol.
    // In each iteration, a packet is sent to the server to a specific port.
    // Then, a new socket is made. A call to recvfrom is made to try to recieve
    // the packet from the server. 
    for(size_t i = 0; i < ports.size(); i++) {
        // Check if port should not be scanned.
        if(portIsIllegal(ports[i])) { continue; }

        // Set up the port at the server.
        serverAddress.sin_port = htons(ports[i]);

        // Send packet to the server.
        int bytesSent = sendto(sockfd, bufferMessage, sizeof(bufferMessage), 0, (struct sockaddr *) &serverAddress, sizeof(serverAddress));
        if(bytesSent < 0) { error("ERROR sending packet"); }
        
        socklen_t r_serverAddress_len = sizeof(r_serverAddress);
        
        // For calculating elapsed time in while loop.
        clock_t startTime = clock();

        memset(rBufferMessage, 0, 65536);

        // Receive packets from server with new socket.
        while(true) {
            int recievedBytes = recvfrom(rsockfd, rBufferMessage, sizeof(rBufferMessage), 0, (struct sockaddr *) &r_serverAddress, &r_serverAddress_len);
            double elapsedTime = double(clock() - startTime);
            // If bytes recieved is more then 0. We go and check if addresses and ports match. 
            // Else we check if time has reached 0.5 sec, then the port is assumed to be open.
            if(recievedBytes > 0) {
                // If the reciever address and the source address are the same, we should
                // see if an error message was sent. 
                // If the addresses are not the same, we ignore the package and look at the next one.
                if(inet_ntoa(serverAddress.sin_addr) == inet_ntoa(r_serverAddress.sin_addr)) {
                    // The IP header.
                    struct iphdr *iphdr = (struct iphdr*) rBufferMessage;
                    long prot = iphdr->protocol;

                    // If prot is 1, then protocol is ICMP.                       
                    if(prot == 1) {
                        closed++;
                        break;

                        /*MSG: Could not find/read the UDP header. So the check on the matching ports could not be made(see code below). */

                        /*
                        unsigned short lenghtOfIPhdr = iphdr->ihl*4;

                        // The ICMP header.
                        struct icmphdr *icmphdr = (struct icmphdr*) (rBufferMessage + sizeof(struct iphdr));

                        // The UDP header.
                        struct udphdr *udphdr = (struct udphdr*) (rBufferMessage + (lenghtOfIPhdr + sizeof(struct icmphdr) + lenghtOfIPhdr));
                        
                        // Check to see if port being scanned and port recieved from match. 
                        // If they match, the port is considered to be closed.
                        // If not, continue and check the next package from recvfrom.
                        
                        if(udphdr->uh_dport == ports[i]) {
                            closed++;
                            cout << "Port: " << ports[i] << " closed ";
                            break;
                        }
                        else { continue; }
                        */
                    }
                    else { continue; }
                }else { continue; }
            }
            else if(elapsedTime > 500000) {
                openPorts.push_back(ports[i]);
                break;
            }
        }
        
        // Wait for half a second plus some random time before next port is scanned.
         if(ports.size() > 1) { usleep(500000 + randomWait()); }
        if(i % 2 == 0) { printScanStatus(i, ports); }
    }
    close(rsockfd);
    printReport(openPorts, closed);
}

unsigned short csum(unsigned short *buffer, int wordCount) {
    unsigned long total;

    for(total = 0; wordCount > 0; wordCount--) {
        total += *buffer++;
    }
    total = (total >> 16) + (total & 0xffff);
    total += (total >> 16);
    return ~total;
}

void fillIpHeader(struct ip_header *iph, struct sockaddr_in sin) {
    iph->ip_hl = 5;
    iph->ip_v = 4;   // for IPV 4
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = 6;
    iph->ip_sum = 0;
    iph->ip_src = inet_addr("192.168.43.17");
    iph->ip_dst = sin.sin_addr.s_addr;
}

void fillTcpHeader(struct tcp_header *tcph, struct sockaddr_in sin) {
    tcph->th_sport = htons(60000);
    tcph->th_dport = sin.sin_port;
    tcph->th_seq = random();
    tcph->th_ack = 0;
    tcph->th_x2 = 0;
    tcph->th_off = 5;
    tcph->th_flags= TH_FIN;
    tcph->th_win = htonl(65535);
    tcph->th_sum = 0;
    tcph->th_urp = 0; 
}

void setTcpFlags(int flag, struct tcp_header *tcph) {
    tcph->th_flags = flag;
}

// Gets a hostname like www.mbl.is and converts to its ip address using addrinfo. 
// Inspiration: https://github.com/angrave/SystemProgramming/wiki/Networking%2C-Part-2%3A-Using-getaddrinfo
int getHostByName(int argc, char *argv[]) {
    struct addrinfo hints, *result;
    struct addrinfo *p;
    char host[256];

    // we zero out addrinfo
    // making sure there is not any bogus there
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    // we use our argument from the command line to retrieve ip number
    // getaddrinfo returns a linked list of addresses
    // on the format number.number.number.number
    int hostValid = getaddrinfo(argv[1], NULL, &hints, &result);
        if(hostValid != 0) {
            printf("Could not retrieve address\n");
        }

        // we loop through the linked list
        // and put the result into host variable
        for (p = result; p != NULL; p = p->ai_next) {
            getnameinfo(p->ai_addr, p->ai_addrlen, host, sizeof(host), NULL, 0,NI_NUMERICHOST);
            puts(host);
        }
        // we free the linked list
        freeaddrinfo(result);

    // we return the address itself
    return inet_addr(host);
}

void FINscan(vector<int> ports, vector<int> openPorts, int closed, int sockfd, int argc, char *argv[]) {
    struct sockaddr_in sin;
   
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);    // ATH: VAR IPPROTO_TCP - Á að vera svona skv. glærum.
    if(sockfd < 0) { error("ERROR opening socket"); }

    for(size_t i = 0; i < ports.size(); i++) {
        if(portIsIllegal(ports[i])) { continue; }

        char packet[4096];
        struct ip_header *iph = (struct ip_header *)packet;
        struct tcp_header *tcph = (struct tcp_header *)(packet + sizeof(struct ip_header));

        bzero((char *) &sin, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(ports[i]);
        sin.sin_addr.s_addr = getHostByName(argc, argv);

        // we fill the ip and tcp header we created.
        // we do this for each new port because of the sequence number.
        fillIpHeader(iph, sin);
        fillTcpHeader(tcph, sin);

        // Urgency pointer. Used if urgent flag is set.
        memset(packet, 0, 4096);
                                        
        // Now that we have set up the packet, we can calculate the IP checksum.
        iph->ip_sum = csum((unsigned short *)packet, (iph->ip_len)>> 1);

        // Here we tell the kernel that we are sending a custom packet so 
        // that it does not make its own.
        int notification = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &notification, sizeof(notification))) { error("ERROR with setsockopt"); } 
        if(sendto(sockfd, packet, iph->ip_len, 0,(struct sockaddr *) &sin, sizeof(sin)) < 0) { error("ERROR with sendto"); }

        if(ports.size() > 1) { usleep(500000 + randomWait()); }

        if(i % 2 == 0) { printScanStatus(i, ports); }
    }
    printReport(openPorts, closed);
}

void SYNscan(vector<int> ports, vector<int> openPorts, int closed, int sockfd, struct sockaddr_in serverAddress) { 
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(sockfd < 0) { error("ERROR opening socket"); }

    for(size_t i = 0; i < ports.size(); i++) {
        if(portIsIllegal(ports[i])) { continue; }

        char packet[4096];
        memset(packet, 0, 4096);

        struct ip *ipHeader = (struct ip*) packet;
        struct tcphdr *tcpHeader = (struct tcphdr*) (packet + sizeof(struct ip));

        serverAddress.sin_port = htons(ports[i]);

        ipHeader->ip_hl = 5;                                             // Header length - 5 unless options
        ipHeader->ip_v = 4;                                              // Header version - We are using IPv4
        ipHeader->ip_tos = 0;                                            // Header type of service. 0 = Normal priority.
        ipHeader->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);    // Normally we would add a payload to be there is none.
        ipHeader->ip_id = htonl(54321);                                  // Does not matter here.
        ipHeader->ip_off = 0;                                            // Fragment offset. Unset.
        ipHeader->ip_ttl = 255;                                          // Time to live. Max = 255. The amount of nodes the packet is allowed to travel before it is discarded.
        ipHeader->ip_p = 6;                                              // Transport layer protocol. We are using the TCP (6).
        ipHeader->ip_sum = 0;                                            // Initially 0. Is calculated later.
        ipHeader->ip_src.s_addr = inet_addr("130.208.240.13");           // Localhost is source.    //TODO: Should be public IP address?
        ipHeader->ip_dst.s_addr = serverAddress.sin_addr.s_addr;             // The input host.

        tcpHeader->th_sport = htons(50000);                              // Source port. Chosen at random.
        tcpHeader->th_dport = serverAddress.sin_port;                    // Destination port. Chosen at random.
        tcpHeader->th_seq = random();                                    // TCP segment sequence is random.
        tcpHeader->th_ack = 0;                                           // ACK sequence is always 0.
        tcpHeader->th_x2 = 0;                                            // Unused, set to zero.
        tcpHeader->th_off = 5;                                           // Segment offset.
        tcpHeader->th_flags = TH_SYN;                                    // Our FIN flag. This is the epicenter of our scan.
        tcpHeader->th_win = htonl(65535);                                // Amount of bytes to be sent before ACK. Maximum allowed size.
        tcpHeader->th_sum = 0;                                           // The OS kernel handles this part.
        tcpHeader->th_urp = 0;                                           // Urgency pointer. Used if urgent flag is set.

        ipHeader->ip_sum = csum((unsigned short *) packet, ipHeader->ip_len >> 1);

        int ntfctn = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &ntfctn, sizeof(ntfctn))) { error("ERROR with sockopt"); }

        int bytesSent = sendto(sockfd, packet, ipHeader->ip_len, 0, (struct sockaddr *) &serverAddress, sizeof(serverAddress));

        // Could not implement receiving and processing the answers because we did not get any when we examined the traffic using Wireshark.
    }
}