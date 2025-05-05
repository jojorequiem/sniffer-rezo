#define _DEFAULT_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_PACKET_SIZE 65536
#define HOSTNAME_SIZE 256
#define LOG_FILE "/var/log/sniffer_rezo.log"

typedef unsigned char u_char;
volatile sig_atomic_t running = 1;

void get_network_info() {
  char hostname[HOSTNAME_SIZE];
  struct hostent *host_info;
  struct in_addr **addr_list;

  if (gethostname(hostname, sizeof(hostname)) != 0) {
    perror("Error getting hostname");
    exit(EXIT_FAILURE);
  }
  printf("Hostname: %s\n", hostname);

  host_info = gethostbyname(hostname);
  if (host_info == NULL) {
    fprintf(stderr, "Error getting host info");
    exit(EXIT_FAILURE);
  }
  addr_list = (struct in_addr **)host_info->h_addr_list;
  printf("Host IP Address: \n");
  printf("%s\n", inet_ntoa(*addr_list[0]));
  printf("\n");
}

void sig_handler(int sig) {
  switch (sig) {
    case SIGUSR1:
      printf("SIGUSR1 received, getting network info...\n");
      fflush(stdout);
      get_network_info();
      break;
    case SIGUSR2:
      running = 0;
      printf("SIGUSR2 received, stopping the sniffer...\n");
      fflush(stdout);
      exit(EXIT_SUCCESS);
      break;
    case SIGTERM:
      printf("SIGTERM received, stopping the sniffer...\n");
      running = 0;
      printf("Sniffer stopped.\n");
      fflush(stdout);
      exit(EXIT_SUCCESS);
      break;
    default:
      break;
  }
}

void packet_handler(u_char *buffer, int size) {
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  char time_str[100];
  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", t);
  printf("[%s] \n", time_str);

  struct ip *ip_header = (struct ip *)(buffer + sizeof(struct ethhdr));
  struct sockaddr_in source, dest;
  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = ip_header->ip_src.s_addr;
  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = ip_header->ip_dst.s_addr;

  const char *protocol;
  int source_port = 0, dest_port = 0;
  switch (ip_header->ip_p) {
    case IPPROTO_TCP: {
      protocol = "TCP";
      struct tcphdr *tcp_header = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
      source_port = ntohs(tcp_header->source);
      dest_port = ntohs(tcp_header->dest);
      break;
    }
    case IPPROTO_UDP: {
      protocol = "UDP";
      struct udphdr *udp_header = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip_header->ip_hl * 4);
      source_port = ntohs(udp_header->source);
      dest_port = ntohs(udp_header->dest);
      break;
    }
    case IPPROTO_ICMP:
      protocol = "ICMP";
      break;
    default:
      protocol = "Unknown";
      break;
  }

  printf("IP Header :\n");
  printf("\t| %-18s : %s\n", "Source IP", inet_ntoa(source.sin_addr));
  printf("\t| %-18s : %s\n", "Destination IP", inet_ntoa(dest.sin_addr));
  if (source_port && dest_port) {
    printf("\t| %-18s : %d\n", "Source Port", source_port);
    printf("\t| %-18s : %d\n", "Destination Port", dest_port);
  }
  printf("\t| %-18s : %s\n", "Protocol", protocol);
  printf("%-18s : %d octets\n", "Captured Packet size", size);
  printf("-----------------------------------\n");
}

void daemonize() {
  pid_t pid;
  struct sigaction sa;

  pid = fork();
  if (pid < 0) {
    perror("Cannot fork");
    exit(EXIT_FAILURE);
  }
  if (pid > 0) {
    exit(EXIT_SUCCESS);
  }

  setsid();

  if ((pid = fork()) < 0) {
    perror("Cannot fork");
    exit(EXIT_FAILURE);
  } else if (pid > 0) {
    exit(EXIT_SUCCESS);
  }

  umask(0);
  chdir("/");

  freopen(LOG_FILE, "a+", stdout);
  freopen(LOG_FILE, "a+", stderr);

  close(STDIN_FILENO);
  open("/dev/null", O_RDONLY);

  sa.sa_handler = sig_handler;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGQUIT, &sa, NULL);
  sigaction(SIGABRT, &sa, NULL);
}

void start_sniffer() {
  int sock_raw;
  struct sockaddr saddr;
  int saddr_len = sizeof(saddr);
  u_char *buffer = (u_char *)malloc(MAX_PACKET_SIZE);

  sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock_raw < 0) {
    perror("Error while creating socket");
    free(buffer);
    exit(EXIT_FAILURE);
  }

  while (running) {
    int data_size = recvfrom(sock_raw, buffer, MAX_PACKET_SIZE, 0, &saddr, (socklen_t *)&saddr_len);
    if (data_size < 0) {
      if (errno == EINTR) {
        continue;
      }
      perror("Error while receiving packet");
      break;
    }
    packet_handler(buffer, data_size);
  }
  close(sock_raw);
  free(buffer);
  printf("Sniffer stopped.\n");
  fflush(stdout);
}

int main() {
  printf("Sniffer started, waiting for packets...\n");
  daemonize();
  get_network_info();
  start_sniffer();
  return EXIT_SUCCESS;
}
