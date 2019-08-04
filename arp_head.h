#pragma once
#include <stdint.h>
#include<stdio.h>
#include<pcap.h>
#include <stdlib.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<unistd.h>
#include<netinet/in.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include <sys/types.h>

typedef struct ARP{
    uint8_t Dmac[6];
    uint8_t Smac[6];
    uint16_t type; //ARP 0806

    uint16_t HwType; //0001
    uint16_t ProtoType; //0800
    uint8_t HwSize; //6
    uint8_t ProtoSize; //4
    uint16_t Opcode; // req = 1 res  = 2

    uint8_t SenderMac[6];
    uint8_t SenderIp[4];
    uint8_t TargetMac[6];
    uint8_t TargetIp[4];
}ARP;
