  
#include <stdio.h>
#include <iostream>
#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <string.h>
#include <vector>
#include <string>


using namespace std;

vector <pair<string,int>> beacon_list;
pcap_t* handle;

struct Radiotap_hdr{
    uint8_t hdr_rev;
    uint8_t hdr_pad;
    uint16_t hdr_len;
    uint64_t present_flags;
    uint64_t MAC_timestamp;
    uint8_t flags;
    uint8_t data_rate;
    uint16_t channel_freq;
    uint16_t channel_flags;
    int8_t antenna_signal;
    uint16_t RX_flags;
    int8_t antenna_signal1;
	uint8_t antenna;
};

struct Beacon_Frame{
    uint8_t FCF[2];        
    uint16_t Duration;
    uint8_t Receiver_MAC[6]; 
    uint8_t Transmitter_MAC[6]; 
    uint8_t BSSID[6];
    uint16_t frag_seq_num;  
};


struct WirelessManage{
	uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t cap_info;
    uint8_t tag_num;
    uint8_t tag_len; 
};

void print_frame(const u_char* packet){
    struct Radiotap_hdr* radio_hdr = (struct Radiotap_hdr*)packet;
    struct Beacon_Frame* beacon = (struct Beacon_Frame*)(packet+radio_hdr->hdr_len);
    struct WirelessManage* wire_manage = (struct WirelessManage*)(packet+radio_hdr->hdr_len+sizeof(struct Beacon_Frame));

    int tag_len = 0;
	char buf[100]={0,};

    if(beacon->FCF[0] != 0x80){
        printf("Not Beacon!\n\n");
        return ;
    }

    printf("BSSID : ");
    for(int i=0;i<5;i++){
        printf("%02x:",beacon->BSSID[i]);
    }
    printf("%02x\n",beacon->BSSID[5]);


    tag_len = wire_manage->tag_len;

    memcpy(buf,(char*)wire_manage+14,wire_manage->tag_len);

    printf("SSID :");

    for(int i=0;i<=tag_len;i++){
        printf("%c",buf[i]);
    }
    printf("\n\n");

}


void usage(){
    cout << "syntax : airodump <interface>"<<endl;
    cout << "sample : airodump mon0"<<endl;
}


int main(int argc, char* argv[]){
    if(argc !=2){ 
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
   
     while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        print_frame(packet);
    }
    
    pcap_close(handle);
}