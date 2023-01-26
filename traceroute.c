// sudo ./prog 9 1.1.1.1
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <stdbool.h> //For bool type
#include <stdint.h>
#include <assert.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
//You have to run it as root because using ICMP requires raw sockets. 
//Regular traceroute with `-I` option (use ICMP instead of UDP) also requires root privileges.
// struct icmphdr
// {
  // u_int8_t type;                /* message type */
  // u_int8_t code;                /* type sub-code */
  // u_int16_t checksum;
  // union
  // {
    // struct
    // {
      // u_int16_t        id;
      // u_int16_t        sequence;
    // } echo;                        /* echo datagram */
    // u_int32_t        gateway;        /* gateway address */
    // struct
    // {
      // u_int16_t        __unused;
      // u_int16_t        mtu;
    // } frag;                        /* path mtu discovery */
  // } un;
// };

// struct iphdr {
// #if defined(__LITTLE_ENDIAN_BITFIELD)
    // __u8    ihl:4,
            // version:4;
// #elif defined (__BIG_ENDIAN_BITFIELD)
    // __u8    version:4,
            // ihl:4;
// #else
// #error "Please fix <asm/byteorder.h>"
// #endif
    // __u8    tos;
    // __be16 -tot_len;
    // __be16 - id;
    // __be16 - frag_off;
    // __u8    ttl;
    // __u8    protocol;
    // __be16 - check;
    // __be32 - saddr;
    // __be32 - daddr;
// };
static uint16_t computeIcmpChecksum(const void *buff, int length) 
{
    uint32_t sum;
    const uint16_t *ptr = buff;
    assert (length % 2 == 0);
    for (sum = 0; length > 0; length -= 2)
	{
		//length=8
		sum += *ptr++;//type+code+pid+sequence(hop、ttl)
	}
    sum = (sum >> 16) + (sum & 0xffff);
    return (uint16_t)(~(sum + (sum >> 16)));//~(sum += (sum >> 16));
}
//有UDP和ICMP兩種方法，一個是等到port unreachable，一個是等到echo reply，我這邊用ICMP
void sendIcmp(int sockfd, const char *ip, uint16_t id, uint16_t sequence, int ttl) 
{
	//填ICMP封包
    struct icmphdr icmp_header;
	memset(&icmp_header, 0, sizeof(icmp_header));
    icmp_header.type = ICMP_ECHO;//8
    icmp_header.code = 0;
    icmp_header.un.echo.id = id;
    icmp_header.un.echo.sequence = sequence;
    icmp_header.checksum = 0;
    icmp_header.checksum = computeIcmpChecksum((uint16_t *)&icmp_header, sizeof(icmp_header));

    struct sockaddr_in recipient;
	memset(&recipient, 0, sizeof(recipient));
    recipient.sin_family = AF_INET;
    int inet_pton_ret = inet_pton(AF_INET, ip, &recipient.sin_addr);
    assert(inet_pton_ret == 1);//inet_pton有問題導致出來的結果不是1的話，中止
	//set ttl on all sockets(uunicast ICMP限定)
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) != 0) 
	{
		perror("setsockopt error"); 
		exit(EXIT_FAILURE);
    }
    int ret = sendto(sockfd, &icmp_header, sizeof(icmp_header), 0, (struct sockaddr *)&recipient, sizeof(recipient));
    if (ret < 0) 
	{
		perror("sendto error"); 
		exit(EXIT_FAILURE);
    }
}

int time_passed(int packets_received, struct timeval *current_time, struct timeval *end_time, int nqueries) 
{
    if (packets_received >= nqueries || timercmp(current_time, end_time, >)){ return 1;}
    return 0;
}

int waitIcmps(int sockfd, uint16_t pid, uint8_t ttl, struct timeval *start_time, struct timeval *end_time, int nqueries) {
    int packets_received = 0;
    int host_reached = 0;
    struct timeval deltas[nqueries];
    struct timeval current_time;

    printf("%d. ", ttl);
    gettimeofday(&current_time, NULL);//tv_sec 是自 1970 年 1 月 1 日午夜 UTC 時間 UNIX 紀元開始以來經過的整數秒數
	//tv_usec 是從 tv_sec 經過的額外微秒數
	//reach到目的地或收到time exceed就會離開迴圈
    while (!time_passed(packets_received, &current_time, end_time, nqueries)) 
	{
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);
        uint8_t buffer[IP_MAXPACKET];
		
		//原本想寫來的socket先做，不等待那種
		//參考https://beej-zhtw-gitbook.netdpi.net/jin_jie_ji_shu/selectff1a_tong_bu_i__o_duo_gong
        // fd_set descriptors;
        // FD_ZERO(&descriptors);//將descriptors這個set的所有位置0，如descriptors在記憶體中佔8位則將descriptors置為00000000
        // FD_SET(sockfd, &descriptors);//將set的第sockfd的位置1，如set原來是00000000，則現在變為10000000，這樣fd==1的檔案描述元就被加進set中了
		// struct timeval tv;
        // timersub(end_time, &current_time, &tv);
		// printf("Wait time : %d,%d\n",tv.tv_sec,tv.tv_usec);
        // int ready = select(sockfd + 1, &descriptors, NULL, NULL, &tv);//tv:要等待的秒數
        // if (ready < 0) 
		// {
			// perror("select error"); 
			// exit(EXIT_FAILURE);
        // } 
		// if (ready == 0) break;

        int packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, 0, (struct sockaddr *)&sender, &sender_len);
        if (packet_len < 0) {perror("recvfrom error"); exit(EXIT_FAILURE);}

        gettimeofday(&current_time, NULL);//收到封包的結束時間
		// printf("start_time %.1f ms ", start_time->tv_usec/1000.0);
		// printf("current_time %.1f ms ", current_time.tv_usec/1000.0);
        char sender_ip_str[20];
        const char *inet_ntop_ret = inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));
        assert(inet_ntop_ret != NULL);//IP為NULL的話，中止

        struct iphdr *ip_header = (struct iphdr *) buffer;
        int ip_header_len = 4 * ip_header->ihl;
		// 取出 ICMP Header
        struct icmphdr *icmp_ptr = (struct icmphdr *)(buffer + ip_header_len);
        uint8_t icmp_type = icmp_ptr->type;
        int proper_type = (icmp_type == ICMP_TIME_EXCEEDED) || (icmp_type == ICMP_ECHOREPLY);
        if (icmp_type == ICMP_TIME_EXCEEDED) 
		{
            struct iphdr *inner_ip_header = (void *) icmp_ptr + 8;
            int inner_ip_header_len = 4 * inner_ip_header->ihl;
            icmp_ptr = (void *)inner_ip_header + inner_ip_header_len;
        }
		//是不是TIME_EXCEEDED、ICMP_ECHOREPLY，送的跟收的ID是否一樣
        if (proper_type && icmp_ptr->un.echo.id == pid && icmp_ptr->un.echo.sequence == ttl) 
		{
            timersub(&current_time, start_time, &deltas[packets_received]);//算發送到接收過了多久
            printf("%s ", sender_ip_str);
            packets_received++;//有收到回應就會++，不管
            if (icmp_type == ICMP_ECHOREPLY)
                host_reached = 1;//終於到目的地了 
        }
    }

    if (packets_received == 0) 
        printf("*");
    else
		for (int i = 0; i < packets_received; i++) 
			printf(" %.1f ms ", deltas[i].tv_usec/1000.0);
        
    printf("\n");
    return host_reached;
}
bool isValidIpAddress(char *ipAddress)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ipAddress, &(sa.sin_addr));
    return result != 0;
}
void startICMP(int inputHop, char *ipAddress)
{
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) 
	{
		perror("socket error"); 
		exit(EXIT_FAILURE);
    }
    u_int16_t pid = getpid();//定義的struct用u_int16_t
	struct timeval startTime, endTime;
	gettimeofday(&startTime, NULL);
	endTime = startTime;
	endTime.tv_sec++;
	sendIcmp(sockfd, ipAddress, pid, inputHop, inputHop);//seq由使用者輸入的hop定義
	int host_reached = waitIcmps(sockfd, pid, inputHop, &startTime, &endTime, 1);
	if (host_reached) printf("Reach destination!\n");//如果你輸入的hop能到目的地的話
	close(sockfd);
}
int main(int argc, char **argv) 
{
	if(geteuid() != 0)
	{
		printf("ERROR: You must be root to use this tool!\n");
		exit(1);
	}
    if (argc != 3) 
	{
        printf("Invalid input.\n");
        return EXIT_FAILURE;
    }
	int i = atoi(argv[1]); 
	if (i < 0 && i > 256) return EXIT_FAILURE ;
    if (isValidIpAddress(argv[2]) != 1) 
	{
        printf("IP address %s is not valid!\n", argv[2]);
        return EXIT_FAILURE;
    }
	startICMP(i,argv[2]);
    return EXIT_SUCCESS;
}