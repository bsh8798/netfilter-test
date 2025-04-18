#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

char *blocked_host;

static u_int32_t get_packet_id(struct nfq_data *tb)
{
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(tb);
    if(ph)
    {
        return ntohl(ph->packet_id);
    }
    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    u_int32_t id = get_packet_id(nfa);

    unsigned char *payload;
    int ret = nfq_get_payload(nfa, &payload);
    if(ret > 0)
    {
        unsigned char *ip_header = payload;
        unsigned char *tcp_header = ip_header + ((ip_header[0] & 0x0f) * 4);

        if(ip_header[9] == 0x06)
        {
            unsigned char *http_payload = tcp_header + ((tcp_header[12] >> 4) * 4);

            if (strncmp((char *)http_payload, "GET ", 4) == 0 || strncmp((char *)http_payload, "POST ", 5) == 0) 
            {
                char *host = strstr((char *)http_payload, "Host: ");
                if (host)
                {
                    host += 6;
                    if (strncmp(host, blocked_host, sizeof(blocked_host)) == 0)
                    {
                        printf("Blocking request to %s\n", host);
                        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                    }
                }
            }
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "syntax : netfilter-test <host>", argv[0]);
        exit(EXIT_FAILURE);
    }

    blocked_host = argv[1];
    printf("blocked_host : %s\n", blocked_host);

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    h = nfq_open();
    if(!h)
    {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }
    if(nfq_unbind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }
    if(nfq_bind_pf(h, AF_INET) < 0)
    {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h, 0, &cb, NULL);
    if(!qh)
    {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }
    if(nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
    {
        fprintf(stderr, "can't set packet_copu mode\n");
        exit(1);
    }

    fd = nfq_fd(h);
    for(;;)
    {
        if((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
        {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if(rv < 0 && errno == ENOBUFS)
        {
            continue;
        }
        break;
    }

    nfq_destroy_queue(qh);
    nfq_close(h);

    exit(0);
}
