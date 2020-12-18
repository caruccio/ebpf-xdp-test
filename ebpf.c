#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/kernel.h>

static inline
int atoo(u8 *ret, unsigned char *payload, void *data_end)
{
    if (payload + 3 > (unsigned char *)data_end) {
        return -1;
    }

    bpf_trace_printk("parse octet: %s", payload);
    *ret = 0;
    int i;
    for (i = 0; i < 3; i++) {
        if (*payload == ' ' || *payload == '.')
            break;

        if (*payload < '0' || *payload > '9')
            return -1;

        *ret = (*ret * 10) + (*payload - '0');
        payload++;
    }
    return i;

}

static inline
int atop(u16 *ret, unsigned char *payload, void* data_end)
{
    if (payload + 5 > (unsigned char *)data_end) {
        return -1;
    }
    bpf_trace_printk("parse port: %s", payload);
    *ret = 0;
    int i;
    for (i = 0; i < 5; i++) {
        if (*payload == ' ')
            break;

        if (*payload < '0' || *payload > '9')
            return -1;

        *ret = (*ret * 10) + (*payload - '0');
        payload++;
    }
    return i;
}

int filter(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    char match_prefix[] = "PROXY TCP4 ";
    char proxy_proto_min_len = 32; //same as strlen("PROXY TCP4 0.0.0.0 0.0.0.0 0 0\r\n")
    char proxy_proto_max_len = 56; //same as strlen("PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n")
    unsigned char buff[1024];
    u32 payload_size, s_ip, d_ip;
    u16 s_port, d_port;
    u8 c;
    int len, i;
    struct ethhdr *eth = data;
    unsigned char *payload_start, *payload;
    struct tcphdr *tcph;
    struct iphdr *iph;

    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    iph = data + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcph = (void *)iph + sizeof(*iph);
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return XDP_PASS;

    bpf_trace_printk("tcp.len=%u", tcph->doff);

    if (tcph->dest != ntohs(7999))
        return XDP_PASS;

    payload_size = ntohs(iph->tot_len) - sizeof(*iph) - (tcph->doff << 2);
    bpf_trace_printk("payload size=%u", payload_size);

    if (payload_size < proxy_proto_min_len)
        return XDP_PASS;

    payload_start = payload = (unsigned char *)tcph + (tcph->doff << 2);
    if (payload + payload_size > (unsigned char *)data_end)
        return XDP_PASS;

    bpf_trace_printk("payload [%s]", payload);

    if (payload + 11 > (unsigned char*)data_end)
        return XDP_PASS;

    if (payload[0] != 'P' && payload[1] != 'R' && payload[2] != 'O' && payload[3] != 'X' && payload[4] != 'Y' && payload[5] != ' ')
        return XDP_PASS;

    if (payload[6] != 'T' && payload[7] != 'C' && payload[8] != 'P' && payload[9] != '4' && payload[10] != ' ')
        return XDP_PASS;

    payload = payload + 11;
    if (payload > (unsigned char*)data_end)
        return XDP_PASS;

    bpf_trace_printk("match prefix [%s]", payload);

    // source IP
    len = atoo(&c, payload, data_end);
    if (len == -1)
        return XDP_PASS;
//    bpf_trace_printk("octet [%u]", c);
    s_ip = c;
    payload = payload + len + 1;

    len = atoo(&c, payload, data_end);
    if (len == -1)
        return XDP_PASS;
//    bpf_trace_printk("octet [%u]", c);
    s_ip |= c <<8;
    payload = payload + len + 1;

    len = atoo(&c, payload, data_end);
    if (len == -1)
        return XDP_PASS;
//    bpf_trace_printk("octet [%u]", c);
    s_ip |= c <<16;
    payload = payload + len + 1;

    len = atoo(&c, payload, data_end);
    if (len == -1)
        return XDP_PASS;
//    bpf_trace_printk("octet [%u]", c);
    s_ip |= c <<24;
    payload = payload + len + 1;

    bpf_trace_printk("source ip [%x]", htonl(s_ip));

    //dest IP
    len = atoo(&c, payload, data_end);
    if (len == -1)
        return XDP_PASS;
//    bpf_trace_printk("octet [%u]", c);
    d_ip = c;
    payload = payload + len + 1;

    len = atoo(&c, payload, data_end);
    if (len == -1)
        return XDP_PASS;
//    bpf_trace_printk("octet [%u]", c);
    d_ip |= c <<8;
    payload = payload + len + 1;

    len = atoo(&c, payload, data_end);
    if (len == -1)
        return XDP_PASS;
//    bpf_trace_printk("octet [%u]", c);
    d_ip |= c <<16;
    payload = payload + len + 1;

    len = atoo(&c, payload, data_end);
    if (len == -1)
        return XDP_PASS;
//    bpf_trace_printk("octet [%u]", c);
    d_ip |= c <<24;
    payload = payload + len + 1;

    bpf_trace_printk("dest ip [%x]", htonl(d_ip));

    //source port
    bpf_trace_printk("payload [%s]", payload);

    len = atop(&s_port, payload, data_end);
    if (len < 1) {
        return XDP_PASS;
    }
    bpf_trace_printk("source port [%u]", s_port);
    payload = payload + len + 1;

    //dest port
    bpf_trace_printk("payload [%s]", payload);

    len = atop(&d_port, payload, data_end);
    if (len < 1) {
        return XDP_PASS;
    }
    bpf_trace_printk("dest port [%u]", d_port);

    if (s_ip == 0x01020304) {
        bpf_trace_printk("DROP");
        tcph->rst = 1;
//        return XDP_DROP;
    }

    bpf_trace_printk("PASS");
    return XDP_PASS;
}
