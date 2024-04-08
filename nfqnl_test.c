#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

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


/* int callback_function(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
 * qh: 큐의 핸들러. 콜백 함수가 어떤 큐에서 호출되었는지 식별하는데 사용
 * nfmsg: 네트워크 메시지에 관한 정보를 담고 있는 구조체
 * nfa: 네트워크 패킷에 관한 데이터를 담고 있는 구조체
 * data: 사용자 정의 데이터, 주로 콜백 함수에서 필요한 추가 정보를 전달하는데 사용
 */
static int my_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark, ifi;
    int ret;
    unsigned char *packet_data;
    
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
        printf("outdev=%u", ifi);
    
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
    printf("dport: %02x %02x\n", packet_data[22], packet_data[23]);
    
    printf("=======================\n");
    printf("entering callback\n");
    fputc('\n', stdout);
    
    char** hex_value = (char**)data;
    for(int i=0; i=4; i++) {
        for(int j=0; hex_value[i][j]!='\0'; j++) {
            printf("%02x", hex_value[i][j]);
        }
        printf("\n");
    }
    
    if (packet_data[22]==0x00 && packet_data[23]==0x50) {
        printf("drop packet\n");
        return nfq_set_verdict(qh, (u_int32_t)id, NF_DROP, 0, NULL);
    }
    else {
        dump(packet_data, ret);
        return nfq_set_verdict(qh, (u_int32_t)id, NF_ACCEPT, 0, NULL);
    }
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
    /* 4096바이트 char 타입의 배열을 정의
     * __attribute__ ((aligned)): gcc 컴파일러에서 사용되는 확장기능으로, 변수나 타입을 특정 바이트 경계에 맞추도록 지시한다.
     * 이 경우 'buf' 배열을 메모리의 바이트 경계에 정렬하도록 지시한다.
     * 일반적으로 이러한 정렬은 성능 향상을 목적으로 하며, 특정 아키텍처에서 메모리 접근이 더 효율적으로 이뤄질 수 있다.
     * 예로 x86 아키텍처에서는 대부분의 데이터 타입이 4 또는 8바이트 경계에 정렬되어 있어야 최적의 성능을 얻을 수 있다.
     */
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    /* libnetfilter_queue 라이브러리를 초기화하고 라이브러리 핸들러를 반환하는 함수이다.
     * 이 핸들러는 네트워크 패킷을 가로채고 처리하는데 사용된다.
     */
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    /* int nfq_unbind_pf(struct nfq_handle *h, u_int16_t pf);
     * 이 함수는 이전에 설정한 패킷 필터를 해제하는데 사용된다. 즉 특정 프로토콜 패밀리에 대한 패킷 필터를 제거하는 역할을 한다.
     * h: 패킷 필터를 해제할 라이브러리 핸들러
     * pf: 패킷 필터를 해제할 프로토콜 패밀리. 보통 AF_INET(IPv4) 또는 AF_INET6(IPv6)가 사용된다.
     * 이 함수는 성공시 0을 실패시 -1을 반환한다. 실패할 경우 errno 변수에 적절한 오류 코드가 설정된다.
     * 일반적으로 이 함수는 이전에 설정한 패킷 필터를 해제할 때 사용된다. 이를 통해 해당 프로토콜 패밀리에 대한 패킷 필터가 제거되어 해당 패킷이 더이상 가로채이지 않는다.
     */
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    /* int nfq_bind_pf(struct nfq_handle *h, u_int16_t pf);
     * 특정 프로토콜 패밀리에 대한 네트워크 패킷을 가로채기 위한 큐를 바인딩 하는 역할을 한다. 이를 통해 해당 프로토콜 패밀리에 대한 패킷을 가로채고 처리할 수 있다.
     * h: 패킷을 가로챌  라이브러리 핸들러
     * pf: 바인딩할 프로토콜 패밀리. 보통 AF_INET(IPv4) 또는 AF_INET6(IPv6)가 사용된다.
     * 이 함수는 성공시 0을 실패시 -1을 반환한다. 실패할 경우 errno 변수에 적절한 오류 코드가 설정된다.
     * 일반적으로 이 함수는 특정 프로토콜 패밀리에 대한 큐를 생성하고 바인딩할 때 사용된다. 
     * 바인딩된 큐는 네트워크 패킷을 받아서 처리할 때 사용된다. 따라서 패키슬 가로채고 처리하기 위해서는 먼저 해당 프로토콜 패밀리에 대한 큐를 바인딩 해야 한다.
     */
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    /* char *host_name[argc];
     * host_name은 포인터 배열이다. 각 포인터는 문자열을 가리키는 포인터이다.
     * host_name[i] 는 문자열을 가리키는 포인터이며 해당 포인터가 가리키는 것은 문자열의 첫 번째 문자이다.
     * host_name[i][j]에서 i는 문자열을 가리키는 포인터이고 j는 해당 문자열의 j번째 문자를 나타낸다.
     * 이는 c언어에서 문자열을 포인터로 처리할 때 흔히 사용되는 방법이다. 문자열을 배열로 생각할 수 있지만, 사실상 문자열은 메모리에서 연속된 문자들의 시퀀스로 표현되므로 포인터를 사용해 각 문자에 직접 접근할 수 있다.
     * 따라서 host_name[i][j]는 host_name[i]가 가리키는 문자열에서 j번째 문자를 의미한다. 이것이 가능한 이유는 host_name이 포인터 배열이고 각 포인터가 문자열을 가리키기 때문이다.
     */
    char* host_name[argc];
    char *hex_value[argc];
    for(int i=0; i<argc; i++) {
        host_name[i] = argv[i];
        
        // 문자열 길이를 구함
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
        /* host_name[i][j]!='\0'는 현재 처리 중인 문자열의 끝에 도달할 때까지 반복문을 실행하는 조건이다.
         * c언어에서 문자열은 null 종단문자('\0' 또는 null character)로 끝난다. 이 null 종단 문자는 문자열의 끝을 표시한다.
         * 따라서 host_name[i][j] != '\0' 조건은 현재 처리 중인 문자열의 문자가 null 종단 문자가 아닌 동안 반복문을 실행한다는 것을 의미합니다. 
         */
        for(int j=0; host_name[i][j]!='\0'; j++) {
            printf("%02x ", hex_value[i][j]);
        }
        
        printf("\n");
    }
    
    printf("binding this socket to queue '0'\n");
    /* struct nfq_q_handle *nfq_create_queue(struct nfq_handle *h, u_int16_t num, nfq_callback *cb, void *data);
     * 네트워크 패킷을 가로채기 위한 큐를 생성하고, 해당 큐에 대한 핸들러를 반환 받을 수 있다.
     * h: 큐를 생성할 라이브러리 핸들러
     * num: 큐의 번호이다. 여러 개의 큐를 생성할 수 있으며, 각 큐는 고유한 번호를 가진다.
     * cb: 패킷을 처리할 콜백 함수의 포인터이다. 이 콜백 함수는 패킷이 도책했을 때 호출되어 패킷을 처리하는 역할을 한다.
     * data: 콜백 함수에 전달할 데이터의 포인터이다. 이 데이터는 콜백 함수에서 필요한 경우에 사용될 수 있다.
     * 이 함수는 성공하면 생성된 큐에 대한 핸들러를 반환, 실패하면 NULL을 반환한다. 실패할 경우 errno 변수에 적절한 오류 코드가 생성된다.
     */
    qh = nfq_create_queue(h,  0, &my_callback, host_name);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    /* int nfq_set_mode(struct nfq_q_handle *qh, nfq_mode mode, u_int32_t range);
     * 네트워크 패킷을 처리하는 큐의 모드를 설정한다. 이 함수를 사용해 큐가 동작하는 방식을 설정할 수 있다.
     * qh: 모드를 설정할 큐의 핸들러
     * mode: 설정할 모드를 지정. 가능한 값은 NFQNL_COPY_PACKET 및 NFQNL_COPY_NONE 등이 있다.
     * - NFQNL_COPY_PACKET: 패킷 데이터를 복사하여 처리한다. 패킷을 수정할 경우 사용된다.
     * - NFQNL_COPY_NONE: 패킷 데이터를 복사하지 않고 직접 처리한다. 패킷을 감시만 할 경우에 사용된다.
     * range: 패킷의 최대 크기를 지정한다. 일반적으로 0xffff로 처리해 모든 패킷을 처리한다.
     */
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    /* int nfq_fd(struct nfq_handle *h);
     * 큐에 대한 파일 디스크럽터를 반환한다. 이 함수를 사용해 큐에 대한 파일 디스크립터를 얻을 수 있다.
     * h: 파일 디스크립터를 얻고자 하는 라이브러리 핸들러
     * 이 파일 디스크립터는 일반적으로 네트워크 패킷을 받아들이고 처리하기 위해 recv() 함수와 함께사용된다.
     * 이 함수를 사용해 파일 디스크립터를 얻은 후 이를 사용해 큐에서 발생하는 이벤트를 감시하고 패킷을 처리할 수 있다.
     */
    fd = nfq_fd(h);

    //for 루프의 초기화, 조건, 증감 부분이 모두 비어있기 때문에 이 루프는 무한히 반복된다. 즉 무한루프이다.
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

