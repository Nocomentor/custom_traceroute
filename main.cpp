#include <iostream>
#include <vector>
#include <set>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <cstdint>
#include <cerrno>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <chrono>

#define TIMEOUT 1000
#define TTL_ITERATIONS 30
#define ECHO_TRIES 3

using namespace std;

struct PID_SEQ {
    uint16_t pid;
    uint16_t seq;
};

struct host_response {
    string host;
    long long time;
};

u_int16_t compute_icmp_checksum(const void *buff, int length)
{
    const uint16_t* ptr = static_cast<const uint16_t*>(buff);
    u_int32_t sum = 0;
    assert (length % 2 == 0);
    for (; length > 0; length -= 2)
        sum += *ptr++;
    sum = (sum >> 16U) + (sum & 0xffffU);
    return (u_int16_t)(~(sum + (sum >> 16U)));
}

void ERROR(const char* str)
{
    perror(str);
    exit(EXIT_FAILURE);
}

struct icmp create_icmp_request(uint16_t id, uint16_t sequence) {

    struct icmp header;

    header.icmp_type = ICMP_ECHO;
    header.icmp_code = 0;
    header.icmp_hun.ih_idseq.icd_id = id;
    header.icmp_hun.ih_idseq.icd_seq = sequence;
    header.icmp_cksum = 0;
    header.icmp_cksum = compute_icmp_checksum( (uint16_t*) &header, sizeof(header) );

    return header;
}

struct sockaddr_in create_recipent(const string& host) {
    struct sockaddr_in recipient;
    memset(&recipient, 0, sizeof(recipient));
    recipient.sin_family = AF_INET;

    if (inet_pton(AF_INET, host.c_str(), &recipient.sin_addr) != 1) {
        ERROR("inet_pton error");
    }

    return recipient;
}

int get_icmp_type(unsigned char* buff) {
    return buff[0];
}

PID_SEQ parse_icmp_response(unsigned char* buff) {
    PID_SEQ result;
    result.pid = (buff[4] << 8) | buff[5];
    result.seq = (buff[6] << 8) | buff[7];
    return result;
}

void print_result(int seq, vector<host_response> responses) {
    cout << seq << ". ";

    if(responses.empty()) {
        cout << "*" << endl;
        return;
    } 

    set<string> unique_hosts;

    for(const auto& response : responses) {
        if (unique_hosts.find(response.host) == unique_hosts.end()) {
            cout << response.host << " ";
            unique_hosts.insert(response.host);
        } 
    }

    if(responses.size() < ECHO_TRIES) {
        cout << "???";
    } else {
        long long sum = 0;
        for(const auto& response : responses) {
            sum += response.time;
        }
        cout << sum / ECHO_TRIES << "ms ";
    }

    cout << endl;
}

bool is_valid_ip(const string& ip) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip.c_str(), &(sa.sin_addr)) != 0;
}

int main(int argc, char* argv[]) {
    if(argc < 2){
        cerr << "Usage: " << argv[0] << " <host>" << endl;
        return EXIT_FAILURE;
    }
    string host = argv[1];

    if(!is_valid_ip(host)) {
        cerr << "Invalid host" << endl;
        cerr << "Usage: " << argv[0] << " <host>" << endl;
        return EXIT_FAILURE;
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        ERROR("socket error");
    }

    struct sockaddr_in recipient = create_recipent(host);

    uint16_t pid = getpid();
    uint16_t icmp_pid = htons(pid);

    struct pollfd fds;
    fds.fd = sockfd;
    fds.events = POLLIN;
    
    for(int i = 1 ; i <= TTL_ITERATIONS ; i++){

        string last_responser = "";

        for(int j = 0 ; j < ECHO_TRIES ; j++){
            struct icmp header = create_icmp_request(icmp_pid, htons(i-1));
        
            int ttl = i;
            if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) < 0) {
                ERROR("setsockopt error");
            }

            ssize_t bytes_sent = sendto(
                sockfd,
                &header,
                sizeof(header),
                0,
                (struct sockaddr*)&recipient,
                sizeof(recipient)
            );
            if (bytes_sent < 0) {
                ERROR("sendto error");
            }
        }
        
        auto start = std::chrono::high_resolution_clock::now();

        vector<host_response> responses;

        while(responses.size() < ECHO_TRIES) {
            int ret = poll(&fds, 1, TIMEOUT);

            if (ret == -1) {
                ERROR("poll error");
            } else if (ret == 0) {
                break;
            }

            if (fds.revents & POLLIN) {
                struct sockaddr_in sender;
                socklen_t sender_len = sizeof(sender);
                u_int8_t buffer[IP_MAXPACKET];

                ssize_t packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, 0, (struct sockaddr*)&sender, &sender_len);
                if (packet_len < 0) {
                    ERROR("recvfrom error");
                }

                char sender_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));

                string responser = string(sender_ip_str);

                struct ip* ip_header = (struct ip*) buffer;
                ssize_t ip_header_len = 4 * (ssize_t)(ip_header->ip_hl);

                int type = get_icmp_type(buffer + ip_header_len);

                last_responser = responser;
                auto end = std::chrono::high_resolution_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

                if (type == 11 || type == 0) {
                    int offset = (type == 11) ? (ip_header_len + 28) : ip_header_len;
                
                    PID_SEQ response = parse_icmp_response(buffer + offset);
                
                    if (response.pid == pid && response.seq == i - 1) {
                        host_response hr;
                        hr.host = responser;
                        hr.time = elapsed.count();
                        responses.push_back(hr);
                    }
                }
            }
        }

        print_result(i, responses);

        if(last_responser == host) {
            break;
        }
    }

    close(sockfd);
    return 0;
}
