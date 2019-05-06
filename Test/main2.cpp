//
// Created by yaozh16 on 2019/4/9.
//

//捕获网络数据包的C++程序
//可以获得数据包长度、通过以太网类型确定上层协议、源以太网地址和目的以太网地址！
#include "pcap.h"
#include<winsock2.h>

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")
#pragma comment(lib,"ws2_32.lib")

/*以下是以太网协议格式*/
struct ether_header
{
    u_int8_t ether_dhost[6]; //目的Mac地址
    u_int8_t ether_shost[6]; //源Mac地址
    u_int16_t ether_type;    //协议类型
};

struct ip_header
{
#if defined(WORDS_BIENDIAN)
    u_int8_t   ip_version:4,
             ip_header_length:4;
#else
    u_int8_t   ip_header_length:4,
            ip_version:4;
#endif
    u_int8_t    ip_tos;
    u_int16_t   ip_length;
    u_int16_t   ip_id;
    u_int16_t   ip_off;
    u_int8_t    ip_ttl;
    u_int8_t    ip_protocol;
    u_int16_t   ip_checksum;
    struct in_addr ip_souce_address;
    struct in_addr ip_destination_address;
};

void ip_protool_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
    struct ip_header *ip_protocol;
    u_int header_length;
    u_int offset;
    u_char tos;
    u_int16_t checksum;
    //MAC首部是14位的，加上14位得到IP协议首部
    ip_protocol = (struct ip_header *) (packet_content+14);
    checksum =ntohs(ip_protocol->ip_checksum);
    tos = ip_protocol->ip_tos;
    offset = ntohs(ip_protocol->ip_off);
    printf("---------IP协议---------\n");
    printf("版本号:%d\n", ip_protocol->ip_version);
    printf("首部长度:%d\n",header_length);
    printf("服务质量:%d\n",tos);
    printf("总长度:%d\n",ntohs(ip_protocol->ip_length));
    printf("标识:%d\n",ntohs(ip_protocol->ip_id));
    printf("偏移:%d\n",(offset & 0x1fff) * 8);
    printf("生存时间:%d\n",ip_protocol->ip_ttl);
    printf("协议类型:%d\n",ip_protocol->ip_protocol);
    switch (ip_protocol->ip_protocol)
    {
        case 1: printf("上层协议是ICMP协议\n");break;
        case 2: printf("上层协议是IGMP协议\n");break;
        case 6: printf("上层协议是TCP协议\n");break;
        case 17: printf("上层协议是UDP协议\n");break;
        default:break;
    }
    printf("检验和:%d\n",checksum);
    printf("源IP地址:%s\n", inet_ntoa(ip_protocol->ip_souce_address));
    printf("目的地址:%s\n", inet_ntoa(ip_protocol->ip_destination_address));
}

void ethernet_protocol_packet_callback(u_char *argument,const struct pcap_pkthdr* packet_header,const u_char* packet_content)
{
    u_short ethernet_type;
    struct ether_header *ethernet_protocol;
    u_char *mac_string;
    static int packet_number = 1;
    printf("----------------------------------------------\n");
    printf("捕获第%d个网络数据包\n",packet_number);
    printf("捕获时间:\n");
    printf("%s",ctime((const time_t*)&packet_header->ts.tv_sec));
    printf("数据包长度:\n");
    printf("%d\n",packet_header->len);
    printf("---------以太网协议---------\n");
    ethernet_protocol=(struct ether_header*)packet_content;//获得数据包内容
    printf("以太网类型:\n");
    ethernet_type=ntohs(ethernet_protocol->ether_type);//获得以太网类型
    printf("%04x\n",ethernet_type);
    switch (ethernet_type)
    {
        case 0x0800: printf("上层协议是IP协议\n");break;
        case 0x0806: printf("上层协议是ARP协议\n");break;
        case 0x8035: printf("上层协议是RARP协议\n");break;
        default:break;
    }
    printf("MAC帧源地址:\n");
    mac_string=ethernet_protocol->ether_shost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
    printf("MAC帧目的地址:\n");
    mac_string=ethernet_protocol->ether_dhost;
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n",*mac_string,*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
    if(ethernet_type==0x0800)//继续分析IP协议
    {
        ip_protool_packet_callback (argument,packet_header,packet_content);
    }
    printf("----------------------------------------------\n");
    packet_number++;
}

int main()
{
    pcap_t* pcap_handle; //winpcap句柄
    char error_content[PCAP_ERRBUF_SIZE]; //存储错误信息
    bpf_u_int32 net_mask; //掩码地址
    bpf_u_int32 net_ip;  //网络地址
    char *net_interface;  //网络接口
    struct bpf_program bpf_filter;  //BPF过滤规则
    char bpf_filter_string[]="ip"; //过滤规则字符串，只分析IPv4的数据包
    net_interface=pcap_lookupdev(error_content); //获得网络接口
    pcap_lookupnet(net_interface,&net_ip,&net_mask,error_content); //获得网络地址和掩码地址
    pcap_handle=pcap_open_live(net_interface,BUFSIZ,1,0,error_content); //打开网络接口
    pcap_compile(pcap_handle,&bpf_filter,bpf_filter_string,0,net_ip); //编译过滤规则
    pcap_setfilter(pcap_handle,&bpf_filter);//设置过滤规则
    if (pcap_datalink(pcap_handle)!=DLT_EN10MB) //DLT_EN10MB表示以太网
        return 0;
    pcap_loop(pcap_handle,10,ethernet_protocol_packet_callback,NULL); //捕获10个数据包进行分析
    pcap_close(pcap_handle);
    return 0;
}