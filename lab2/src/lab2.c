#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h> // �Ω�i�ܰѼ�
#include "arp.h"
#include "netdevice.h"
#include "util.h"

#define ARP_TABLE_SIZE 10

/* �H���� ARP �� */
typedef struct {
    uint8_t ip[4];
    uint8_t mac[6];
} arptable_entry_t;

arptable_entry_t arptable[ARP_TABLE_SIZE];
int arptable_count = 0;

/* ���a�����t�m */
uint8_t myethaddr[] = { 0x00, 0x15, 0x5d, 0xbc, 0x06, 0x73 };
uint8_t myipaddr[] = { 172, 17, 151, 35 };
uint8_t defarpip[] = { 172, 17, 144, 1 };

/* ��x�������ܼ� */
FILE* log_file;

/*
 * log_message() - �g�J��x���ÿ�X�챱��x
 */
void log_message(const char* format, ...) {
    va_list args;

    // �N������X�챱��x
    va_start(args, format);
    vprintf(format, args);
    va_end(args);

    // �P�ɼg�J���x���
    if (log_file) {
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
    }
}

/*
 * arptable_existed() - �ˬd ARP ���O�_�s�b������ IP �a�}
 * \return �p�G���A��^������ MAC �a�}�F�p�G�䤣��A��^ NULL�C
 */
uint8_t* arptable_existed(uint8_t* ipaddr) {
    for (int i = 0; i < arptable_count; i++) {
        if (memcmp(arptable[i].ip, ipaddr, 4) == 0) {
            return arptable[i].mac;
        }
    }
    return NULL;
}

/*
 * arptable_add() - �N�s�� IP-MAC �M�g�K�[�� ARP ��
 */
void arptable_add(uint8_t* ip, uint8_t* mac) {
    if (arptable_count >= ARP_TABLE_SIZE) {
        log_message("[Warning!] ARP table is full, unable to add more entries.\n");
        return;
    }
    memcpy(arptable[arptable_count].ip, ip, 4);
    memcpy(arptable[arptable_count].mac, mac, 6);
    arptable_count++;
    log_message("[INFO] Added to ARP table: IP=%d.%d.%d.%d, MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
        ip[0], ip[1], ip[2], ip[3], mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
 * detect_arp_spoof() - �˴� ARP ���F
 */
void detect_arp_spoof(uint8_t* ip, uint8_t* mac) {
    uint8_t* expected_mac = arptable_existed(ip);
    if (expected_mac != NULL && memcmp(expected_mac, mac, 6) != 0) {
        log_message("[Warning!] ARP spoofing detected! IP=%d.%d.%d.%d, MAC=%02x:%02x:%02x:%02x:%02x:%02x (expected %02x:%02x:%02x:%02x:%02x:%02x)\n",
            ip[0], ip[1], ip[2], ip[3], mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            expected_mac[0], expected_mac[1], expected_mac[2], expected_mac[3], expected_mac[4], expected_mac[5]);
    }
}

/*
 * main_proc() - �D�{���޿�
 */
int main_proc(netdevice_t* p) {
    int key;
    char buf[MAX_LINEBUF];
    ipaddr_t ip;

#if (FG_ARP_SEND_REQUEST == 1)
    /*
     * �o�e ARP �ШD���q�{ IP �a�}
     */
    arp_request(p, defarpip);
#endif /* FG_ARP_REQUEST */

    while (1) {
        /*
         * �B�z���򪺼ƾڥ]
         */
        if (netdevice_rx(p) == -1) {
            break;
        }

        /* ��L�޿�i�H���J���B */

        /*
         * �˴��O�_���Τ��J
         */
        if (!readready()) {
            continue;
        }
        /* �p�G�Τ���U�^����A�h�X�{�� */
        if ((key = fgetc(stdin)) == '\n') {
            break;
        }
        ungetc(key, stdin);
        if (fgets(buf, MAX_LINEBUF, stdin) == NULL) {
            break;
        }
        if ((ip = retrieve_ip_addr(buf)) == 0) {
            log_message("Invalid IP address (press enter to exit).\n");
        }
        else {
            arp_request(p, (unsigned char*)&ip);
        }
    }

    return 0;
}

int main(int argc, char* argv[]) {
    char devname[MAX_LINEBUF], errbuf[PCAP_ERRBUF_SIZE];
    netdevice_t* p;

    /*
     * ���}��x���
     */
    log_file = fopen("log.txt", "a");
    if (!log_file) {
        fprintf(stderr, "Unable to open log file.\n");
        return -1;
    }

    /*
     * ����������f�W��
     */
    if (argc == 2) {
        strcpy(devname, argv[1]);
    }
    else if (netdevice_getdevice(0, devname) == NETDEVICE_ERR) {
        return -1;
    }

    /*
     * ���}���w�����f
     */
    if ((p = netdevice_open(devname, errbuf)) == NULL) {
        fprintf(stderr, "Unable to open capture interface\n\t%s\n", errbuf);
        fclose(log_file);
        return -1;
    }
    log_message("Capturing packets on interface %s\n", devname);

    /*
     * ���U�S�w��ĳ���ƾڥ]�B�z�^��
     */
    netdevice_add_proto(p, ETH_ARP, (ptype_handler)&arp_main);

    main_proc(p);

    /*
     * �M�z�귽
     */
    netdevice_close(p);
    fclose(log_file);
    return 0;
}
