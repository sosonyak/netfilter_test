#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <regex.h>
#include <string.h>

#define TCP 6


struct return_tuple{
    int id_val;
    int harm_check;
};


int find_HarmWeb(const char* data_buf, const char* harm_web){
    regex_t regex;
    int reti;

    char* host_name = (char*)malloc(strlen("Host: ") + strlen(harm_web) + 1);

    if (host_name == NULL) {
        fprintf(stderr, "Memory allocation failed during HOST declaration\n");
        regfree(&regex);
        return -1;
    }

    strcpy(host_name, "Host: ");
    strcat(host_name, harm_web);
    printf("[ host name ]\n%s\n", host_name);

    reti = regcomp(&regex, host_name, 0);
    reti = regexec(&regex, data_buf, 0, NULL, 0);
    if (!reti){
        regfree(&regex);
        free(host_name);
        return 1;
    }

    regfree(&regex);
    return 0;
}

int dump(unsigned char* buf, int size, const char* harm_web) {
    int protocol = buf[9];
    // printf("protocol: %d\n", protocol);

    if (protocol == TCP){
        int ip_len = (buf[0]&0x0f)*4;
        int tcp_flag = 0;
        int http_flag = 0;

        volatile int data_offset = 12;
        int n = ip_len + data_offset;
        data_offset = ip_len + ((buf[n]>>4)&0x0f)*4;
        // printf("data_offset: %d\n", data_offset);

        char* ip = (char*)malloc(ip_len);
        char* tcp = (char*)malloc(8);
        char* http = (char*)malloc(8);

        if ((size-data_offset) > 0){
            char* tcp_new = (char*)realloc(tcp, data_offset-ip_len);
            if (tcp_new == NULL){
                printf("TCP Memory realloc failed\n");
            }
            else {
                tcp = tcp_new;
                tcp_flag = 1;
            }

            char* http_new = (char*)realloc(http, size-data_offset);
            if (http_new == NULL){
                printf("HTTP Memory realloc failed\n");
            }
            else {
                http = http_new;
                http_flag = 1;
            }

            // printf("[size]\ttotal: %d\nip: %d\ntcp: %d\nhttp: %d\n\n", size, ip_len, data_offset-ip_len, size-data_offset);

            int buf_size = 0;
            for (int i = data_offset; i < size-data_offset; i++) {
                if (buf[i] == '\0') {
                    http[buf_size] = '\0';
                    break;
                }
                http[buf_size++] = buf[i];
            }

            printf("[ HTTP ]\n%s\n", http);

            int result = find_HarmWeb(http, harm_web);

            free(ip);
            if (tcp_flag != 0) free(tcp);
            if (http_flag != 0) free(http);

            if (result == 1){
                return 1;
            }
        }
    }
}


/* returns packet id */
struct return_tuple print_pkt (struct nfq_data *tb, const char* harm_web)
{    
    int id = 0;
    int harm_check = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0){
        printf("payload_len=%d\n", ret);
        harm_check = dump(data, ret, harm_web);
    }
    fputc('\n', stdout);

    struct return_tuple t = {id, harm_check};

    return t;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void* data)
              // struct nfq_data *nfa, const char* harm_web)
{
    char* harm_web = (char*) data;
    // printf("[ str check ] %s\n", harm_web);
    struct return_tuple tuple = print_pkt(nfa, harm_web);
    // printf("id: %d, harm check flag: %d\n\n", tuple.id_val, tuple.harm_check);

    printf("entering callback\n");
    if (tuple.harm_check != 0)
        return nfq_set_verdict(qh, tuple.id_val, NF_DROP, 0, NULL);
    else
        return nfq_set_verdict(qh, tuple.id_val, NF_ACCEPT, 0, NULL);
}


void jump_to_nq(){
    FILE *fp;
    char buf[1024];

    fp = popen("sudo iptables -L", "r");
    if (fp == NULL){
        printf("Failed to get iptable list");
        exit(1);
    }

    regex_t regex;
    int reti;
    char *pattern = "NFQUEUE";

    reti = regcomp(&regex, pattern, 0);

    while (fgets(buf, sizeof(buf), fp) != NULL){
        reti = regexec(&regex, buf, 0, NULL, 0);
        if (!reti){
            system("sudo iptables -F");
        }
    }

    pclose(fp);
    regfree(&regex);

    system("sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    system("sudo iptables -A INPUT -j NFQUEUE --queue-num 0");
}


void usage() {
    printf("syntax: netfilter-test <host>\n");
    printf("sample: netfilter-test test.gilgil.net\n");
}


int main(int argc, char **argv)
{
    if (argc != 2) {
        usage();
        return -1;
    }

    void* harmful_web = (void*)argv[1];
    printf("harmful web site name: %s\n", harmful_web);

    jump_to_nq();

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

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
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    // qh = nfq_create_queue(h,  0, &cb, NULL);
    qh = nfq_create_queue(h,  0, &cb, harmful_web);
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
