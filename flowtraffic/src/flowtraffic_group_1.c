#include "./flowtraffic_group_1.h"

int main(int argc, char *argv[]) {

    char errbuf[PCAP_ERRBUF_SIZE], *dev = NULL;
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net = 0;

    if (argc > 1)
        dev = argv[1];
    if (!dev)
        dev = pcap_lookupdev(errbuf); // deprecated
    if (!dev) {
        fprintf(stderr, "找不到可用网卡: %s\n", errbuf);
        return 1;
    }

    printf("监听接口: %s\n", dev);
    get_local_ip(dev);
    printf("本机IPv4: %s\n", local_ipv4);
    printf("本机IPv6: %s\n", local_ipv6);

    handle = pcap_open_live(dev, 65535, 1, 1000, errbuf);

    if (!handle) {
        fprintf(stderr, "无法打开接口: %s\n", errbuf);
        return 2;
    }

    if (pcap_compile(handle, &fp, "ip or ip6", 0, net) == -1) {
        fprintf(stderr, "过滤规则编译失败\n");
        return 3;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "设置过滤规则失败\n");
        return 4;
    }

    signal(SIGINT, handle_sig);
    signal(SIGTERM, handle_sig);

    ///@brief 数据包捕获线程

    sleep(1.5);

    pthread_t tid;
    pthread_create(&tid, NULL, show_thread, NULL);

    while (!stop_flag) {
        // 与pcap_loop的不同在于, dispatch不会忽略pcap_open_live设置的超时
        int res = pcap_dispatch(handle, 10, packet_handler, NULL);
        if (res == -1)
            break;
    }

    pcap_close(handle);
    pthread_join(tid, NULL);
    printf("\n退出...\n");
    return 0;
}
