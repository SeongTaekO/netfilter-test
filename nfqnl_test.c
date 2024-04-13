#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <stdbool.h>
#include <pcre.h>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}


int param_num = 0;

static int my_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *packet_data;
    
    printf("entering callback\n");
    
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocoe=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
    }
    
    hwph = nfq_get_packet_hw(nfa);
    if (hwph) {
        int hlen = ntohs(hwph->hw_addrlen);
        
        printf("hw_src_addr=");
        for (int i=0; i<hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }
    
    mark = nfq_get_nfmark(nfa);
    if (mark)
        printf("mark=%u ", mark);
    
    ifi = nfq_get_indev(nfa);
    if (ifi)
        printf("indev=%u ", ifi);
    
    ifi = nfq_get_outdev(nfa);
    if (ifi)
        printf("outdev=%u ", ifi);
    
    ifi = nfq_get_physindev(nfa);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(nfa);
    if (ifi)
        printf("physoutdev=%u ", ifi);
	
    ret = nfq_get_payload(nfa, &packet_data);
    if (ret >= 0) {
        printf("payload_len=%d\n", ret);
    }
    
    fputc('\n', stdout);
    
    char** hex_value = (char**)data;
    for (int i=1; i<param_num; i++) {
        bool match = false;
        bool port_match = false;
        const char *pattern = hex_value[i];
        const char *error;
        int erroffset;
        int rc;
        pcre *re;
        int ovector[30];
        
        re = pcre_compile(pattern, 0, &error, &erroffset, NULL);
        if(re == NULL) {
            printf("Error compiling regex: %s\n", error);
            exit(1);
        }
        
        rc = pcre_exec(re, NULL, packet_data, ret, 0, 0, ovector, 30);
        
        if(rc > 0 && ovector[1] - ovector[0] == strlen(pattern)) {
            match = true;
            printf("matched!\n");
        }
        else {
            match = false;
            printf("not matched!\n");
        }
        
        if(packet_data[22]==0x00 && packet_data[23]==0x50) {
            port_match = true;
        }
        
        if(match && port_match) {
            printf("destination port: %02x %02x\n", packet_data[22], packet_data[23]);
            printf("drop packet\n");
            printf("=======================\n");
            return nfq_set_verdict(qh, (u_int32_t)id, NF_DROP, 0, NULL);
        }
    }

    dump(packet_data, ret);
    printf("destination port: %02x %02x\n", packet_data[22], packet_data[23]);
    printf("=======================\n");
    return nfq_set_verdict(qh, (u_int32_t)id, NF_ACCEPT, 0, NULL);
}

void usage() {
    printf("type host dns\n");
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}

int main(int argc, char **argv)
{
    if (argc <= 1) {
        usage();
        return -1;
    }

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    
    param_num = argc;

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    char* host_name[argc];
    char *hex_value[argc];
    for(int i=0; i<argc; i++) {
        host_name[i] = argv[i];
        
        int len = 0;
        while(host_name[i][len]) {
            len++;
        }
        
        hex_value[i] = (char*)malloc(len * sizeof(char));
        if(hex_value[i]==NULL) {
            fprintf(stderr, "Memory allocation failed\n");
            exit(1);
        }
        
        for(int j=0; j<len; j++) {
            hex_value[i][j] = host_name[i][j];
        }
    }
    
    for(int i=0; i<argc; i++) {
        char *current_char = host_name[i];
        
        printf("%s: ", current_char);
        for(int j=0; host_name[i][j]!='\0'; j++) {
            printf("%02x ", hex_value[i][j]);
        }
        
        printf("\n");
    }
    
    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &my_callback, host_name);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    
    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

