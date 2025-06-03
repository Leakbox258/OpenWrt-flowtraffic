#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define MAX_FLOWS 256
#define MAX_FLOWS_IN_ONE_PAGE 42
#define MAX_HOSTLEN 128
#define INTERVALS 3
#define max(a, b) a > b ? a : b
#define min(a, b) a < b ? a : b

typedef unsigned char u_char;

int interval_seconds[INTERVALS] = {2, 10, 40}; // 可自定义

char proto_strings[5][8] = {"UNKNOWN", "UDP", "TCP", "ICMP", "ICMPV6"};

// 每条流的统计结构
typedef struct {
    char src[INET6_ADDRSTRLEN];
    uint32_t sport;
    char dst[INET6_ADDRSTRLEN];
    uint32_t dport;
    char host[MAX_HOSTLEN];
    int ipProto;
    char direction[3];                           // "=>" or "<="
    unsigned long bytes_per_interval[INTERVALS]; // 当前区间累计
    time_t last_time[INTERVALS];                 // 区间起始时间
    double avg_per_sec[INTERVALS];               // 上一次统计结果
    double peak_per_sec[INTERVALS];              // 峰值记录
} FlowInfo;

// 记录从程序开始到stop为止所有流的统计, 无淘汰机制
FlowInfo flows[MAX_FLOWS];

int flow_count = 0;
pthread_mutex_t flow_lock = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t stop_flag = 0;

char local_ipv4[INET_ADDRSTRLEN] = "";
char local_ipv6[INET6_ADDRSTRLEN] = "";

// 清屏
void cls() { printf("\ec"); }

// 获取本机IP地址
void get_local_ip(const char *dev) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1)
        return;

    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        printf("正检查接口: %s\n", ifa->ifa_name);

        if (!ifa->ifa_addr || strcmp(ifa->ifa_name, dev) != 0) {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_INET) {

            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &(sin->sin_addr), local_ipv4, sizeof(local_ipv4));

        } else if (ifa->ifa_addr->sa_family == AF_INET6) {

            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &(sin6->sin6_addr), local_ipv6, sizeof(local_ipv6));
        }
    }

    freeifaddrs(ifaddr);
}

// 字段	长度（字节）	示例值（十六进制）	说明
// 事务 ID	2	0x1234	随机标识，用于匹配请求与响应
// 标志（Flags）	2	0x0100	标准查询（RD=1，其他标志为 0）
// 问题数	2	0x0001	查询数量（通常为 1）
// 应答数	2	0x0000	响应中才有值，请求中为 0
// 权威记录数	2	0x0000	请求中为 0
// 附加记录数	2	0x0000	请求中为 0
// 查询域名	可变	03 77 77 77 07 65 78 61 6D 70 6C 65 03 63 6F 6D 00	www.example.com 的编码
// 查询类型	2	0x0001	A 记录（IPv4）
// 查询类	2	0x0001	IN（Internet）

// DNS域名提取（超简易，仅A查询）
void parse_dns(const u_char *payload, int len, char *out, int outlen) { // out = host
    if (len < 12)
        return;                                      // DNS头
    int qdcount = ntohs(*(uint32_t *)(payload + 4)); // 问题数
    if (qdcount < 1)
        return;
    int pos = 12; // 跳过DNS头
    int i = 0;
    while (pos < len && i < outlen - 1) {
        int l = payload[pos++];
        if (l == 0)
            break;
        if (l > 63 || pos + l > len)
            break;
        if (i)
            out[i++] = '.';
        memcpy(out + i, payload + pos, l);
        i += l;
        pos += l;
    }
    out[i] = 0;
}

// 判断方向, 直接匹配ip字符串
void calc_direction(const char *src, const char *dst, char *dir) {
    if ((local_ipv4[0] && strcmp(src, local_ipv4) == 0) // NOLINT
        || (local_ipv6[0] && strcmp(src, local_ipv6) == 0)) {

        strcpy(dir, "=>"); // send

    } else if ((local_ipv4[0] && strcmp(dst, local_ipv4) == 0) // NOLINT
               || (local_ipv6[0] && strcmp(dst, local_ipv6) == 0)) {

        strcpy(dir, "<="); // recv

    } else {

        strcpy(dir, "??"); // send(defualt)
    }
}

// 查找/插入流（并初始化区间时间）
FlowInfo *find_or_create_flow(const char *src, uint32_t *sport, const char *dst, uint32_t *dport, int *ipProto,
                              const char *host, const char *dir) {
    // find
    for (int i = 0; i < flow_count; i++) {
        if (strcmp(flows[i].src, src) == 0 && strcmp(flows[i].dst, dst) == 0 && strcmp(flows[i].host, host) == 0 &&
            strcmp(flows[i].direction, dir) == 0 && flows[i].sport == *sport && flows[i].dport == *dport &&
            flows[i].ipProto == *ipProto) {

            ///@note 会出现相同的src, dst, 但是sport, dport不同的情况
            return &flows[i];
        }
    }

    // create
    if (flow_count < MAX_FLOWS) {

        FlowInfo *f = &flows[flow_count++];
        memset(f, 0, sizeof(FlowInfo));
        strncpy(f->src, src, sizeof(f->src) - 1);
        f->sport = *sport;
        strncpy(f->dst, dst, sizeof(f->dst) - 1);
        f->dport = *dport;
        strncpy(f->host, host, sizeof(f->host) - 1); // 不一定有
        f->ipProto = *ipProto;
        strncpy(f->direction, dir, 2);
        time_t now = time(NULL);
        for (int i = 0; i < INTERVALS; i++) {
            f->last_time[i] = now;
            f->bytes_per_interval[i] = 0;
            f->avg_per_sec[i] = 0;
            f->peak_per_sec[i] = 0;
        }
        return f;
    }

    return NULL;
}

// 更新流量，注意区间逻辑
void update_flow(const char *src, uint32_t *sport, const char *dst, uint32_t *dport, int *ipProto, const char *host,
                 const char *dir, unsigned long bytes) {
    pthread_mutex_lock(&flow_lock);
    FlowInfo *f = find_or_create_flow(src, sport, dst, dport, ipProto, host, dir);

    if (f) {
        time_t now = time(NULL);
        for (int i = 0; i < INTERVALS; i++) {
            // 区间过期(2s, 10s, 40s)，计算平均速率并重置
            if (now - f->last_time[i] >= interval_seconds[i]) {
                double avg = (double)f->bytes_per_interval[i] / interval_seconds[i];
                f->avg_per_sec[i] = avg;

                // 更新峰值
                f->peak_per_sec[i] = max(avg, f->peak_per_sec[i]);

                f->bytes_per_interval[i] = 0;
                f->last_time[i] = now;
            }
            f->bytes_per_interval[i] += bytes;
        }
    }
    pthread_mutex_unlock(&flow_lock);
}

// 定期刷新区间，避免无新包时速率不跟新
void refresh_flow_intervals() {
    pthread_mutex_lock(&flow_lock);
    time_t now = time(NULL);

    for (int j = 0; j < flow_count; j++) {
        for (int i = 0; i < INTERVALS; i++) {
            if (now - flows[j].last_time[i] >= interval_seconds[i]) {
                double avg = (double)flows[j].bytes_per_interval[i] / interval_seconds[i];
                flows[j].avg_per_sec[i] = avg;
                // 更新峰值
                if (avg > flows[j].peak_per_sec[i])
                    flows[j].peak_per_sec[i] = avg;

                flows[j].bytes_per_interval[i] = 0;
                flows[j].last_time[i] = now;
            }
        }
    }
    pthread_mutex_unlock(&flow_lock);
}

// 统计展示线程
void *show_thread(void *arg) {
    while (!stop_flag) {
        cls();

        int flow_show_begin = 0;
        int page_count = (flow_count + MAX_FLOWS_IN_ONE_PAGE - 1) / MAX_FLOWS_IN_ONE_PAGE;

        // 始终显示最后一页
        if (page_count > 0) {
            flow_show_begin = max(0, flow_count - MAX_FLOWS_IN_ONE_PAGE);
        }

        printf("\033[32m已有流数: %d, 已隐藏: %d\nlast modified by LeakBox258\n\033", flow_count, page_count);

        printf("\033[31m%-36s %-3s %-36s\033[0m", "SRC", "DIR", "DST/HOST");
        printf("\033[31m%-8s%-8s", "SPORT", "DPORT\033");
        printf("\033[31m   %-8s\033", "PROTO");

        for (int i = 0; i < INTERVALS; i++)
            printf("     \033[31m %ds(Avg/Peak)\033[0m   ", interval_seconds[i]);

        printf("\n\n");

        refresh_flow_intervals(); // 保证超时流也更新速率

        pthread_mutex_lock(&flow_lock);

        for (int i = page_count; i < flow_count; i++) {
            printf("\033[33m%-36s\033[0m \033[32m%-3s\033[0m \033[36m%-36s\033[0m", flows[i].src, flows[i].direction,
                   flows[i].host[0] ? flows[i].host : flows[i].dst); // show dns host if dont exsist then show dst

            if (flows[i].sport != -1)
                printf("\033[33m%-8u\033", flows[i].sport);
            else
                printf("\033[33m~       \033");

            if (flows[i].dport != -1)
                printf("\033[36m%-8u\033", flows[i].dport);
            else
                printf("\033[33m~       \033");

            printf("\033[32m%-8s\033[0m", proto_strings[flows[i].ipProto]);

            for (int j = 0; j < INTERVALS; j++) {
                printf(" %8.1f/%-8.1fB ", flows[i].avg_per_sec[j], flows[i].peak_per_sec[j]);
            }

            printf("\n");
        }
        fflush(stdout);

        pthread_mutex_unlock(&flow_lock);
        sleep(1);
    }
}

// 信号处理
void handle_sig(int sig) { stop_flag = 1; }

void packet_handler_ipv4(const u_char *packet, int offset, int pkt_len, char src[INET6_ADDRSTRLEN], uint32_t *sport,
                         char dst[INET6_ADDRSTRLEN], uint32_t *dport, int *ipProto, char host[MAX_HOSTLEN]) {
    // 以太网帧转为ip数据报

    struct ip *iphdr = (struct ip *)(packet + offset);
    inet_ntop(AF_INET, &(iphdr->ip_src), src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iphdr->ip_dst), dst, INET6_ADDRSTRLEN);
    int nh = iphdr->ip_p;
    int hdrlen = iphdr->ip_hl * 4;

    if (nh == IPPROTO_UDP) { // UDP
        *ipProto = 1;

        // skip ip header
        struct udphdr *udp = (struct udphdr *)((u_char *)iphdr + hdrlen);
        *sport = ntohs(udp->uh_sport), *dport = ntohs(udp->uh_dport);

        if (*sport == 53 || *dport == 53) { // DNS
            const u_char *dns = (u_char *)udp + sizeof(struct udphdr);
            int dnssz = pkt_len - offset - hdrlen - sizeof(struct udphdr);
            parse_dns(dns, dnssz, host, MAX_HOSTLEN);
        }

    } else if (nh == IPPROTO_TCP) { // TCP
        *ipProto = 2;

        // skip ip header
        struct tcphdr *tcp = (struct tcphdr *)((u_char *)iphdr + hdrlen);
        *sport = ntohs(tcp->th_sport), *dport = ntohs(tcp->th_dport);

        if (*sport == 53 || *dport == 53) {
            const u_char *dns = (u_char *)tcp + sizeof(struct tcphdr);
            int dnssz = pkt_len - offset - hdrlen - sizeof(struct tcphdr);
            parse_dns(dns, dnssz, host, MAX_HOSTLEN);
        }

    } else if (nh == IPPROTO_ICMP) {
        *ipProto = 3;
    }
}

void packet_handler_ipv6(const u_char *packet, int offset, int pkt_len, char src[INET6_ADDRSTRLEN], uint32_t *sport,
                         char dst[INET6_ADDRSTRLEN], uint32_t *dport, int *ipProto, char host[MAX_HOSTLEN]) {

    struct ip6_hdr *ip6 = (struct ip6_hdr *)(packet + offset);
    inet_ntop(AF_INET6, &(ip6->ip6_src), src, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6->ip6_dst), dst, INET6_ADDRSTRLEN);
    int nh = ip6->ip6_nxt;
    int hdrlen = sizeof(struct ip6_hdr);

    if (nh == IPPROTO_UDP) { // UDP
        *ipProto = 1;

        struct udphdr *udp = (struct udphdr *)((u_char *)ip6 + hdrlen);
        *sport = ntohs(udp->uh_sport), *dport = ntohs(udp->uh_dport);

        if (*sport == 53 || *dport == 53) {
            const u_char *dns = (u_char *)udp + sizeof(struct udphdr);
            int dnssz = pkt_len - offset - hdrlen - sizeof(struct udphdr);
            parse_dns(dns, dnssz, host, MAX_HOSTLEN);
        }

    } else if (nh == IPPROTO_TCP) { // TCP
        *ipProto = 2;

        // skip ip header
        struct tcphdr *tcp = (struct tcphdr *)((u_char *)ip6 + hdrlen);
        *sport = ntohs(tcp->th_sport), *dport = ntohs(tcp->th_dport);

        if (*sport == 53 || *dport == 53) {
            const u_char *dns = (u_char *)tcp + sizeof(struct tcphdr);
            int dnssz = pkt_len - offset - hdrlen - sizeof(struct tcphdr);
            parse_dns(dns, dnssz, host, MAX_HOSTLEN);
        }
    } else if (nh == IPPROTO_ICMPV6) {
        *ipProto = 4;
    }
}

// 主要数据包处理
// Ethe头部(14): dst(6), src(6), type(2)
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    char src[INET6_ADDRSTRLEN] = "", dst[INET6_ADDRSTRLEN] = "", host[MAX_HOSTLEN] = "", dir[3] = "";
    uint32_t sport = -1, dport = -1;
    int ipProto = 0;
    unsigned short eth_type = ntohs(*(unsigned short *)(packet + 12));
    unsigned long pkt_len = pkthdr->len; // MAC帧长度
    int offset = 14;                     // 以太网头

    if (eth_type == ETHERTYPE_IP) {
        packet_handler_ipv4(packet, offset, pkt_len, src, &sport, dst, &dport, &ipProto, host);
    } else if (eth_type == ETHERTYPE_IPV6) {
        packet_handler_ipv6(packet, offset, pkt_len, src, &sport, dst, &dport, &ipProto, host);
    } else {
        return; // 只处理IP包
    }

    calc_direction(src, dst, dir);

    // 有新包, 触发增添新速率 + 刷新旧速率
    update_flow(src, &sport, dst, &dport, &ipProto, host, dir, pkt_len); // pkt_len = btype_cnt
}