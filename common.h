#pragma once

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

// custom bool type since C doesn't have one
typedef enum {
   false = 0,
   true = 1
} bool;

#define CLEAR(structure) memset(&structure, 0, sizeof(structure));
#define STATIC_ASSERT(condition, message) typedef char static_assertion_##message[(condition) ? 1 : -1]

void printf_debug(const char* format, ...) 
{
   (void)format;
#if DEBUG
   printf("[debug] ");
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
#endif
}

void print_errno(const char* prefix, const char* message, int32_t error)
{
   char buffer[256];
   strerror_r(error, buffer, sizeof(buffer));
   printf("%s: %s [ %s ]\n", prefix, message, buffer);
}

// current monotonic time in milliseconds
uint64_t get_current_timestamp()
{
   struct timespec spec;
   if (clock_gettime(CLOCK_MONOTONIC, &spec) == -1)
      return 0;

   return spec.tv_sec * 1000 + spec.tv_nsec / 1e6;
}

bool address_is_localhost(const struct sockaddr_storage* address)
{
   if (address->ss_family == AF_INET)
   {
      struct sockaddr_in localhost;
      localhost.sin_addr.s_addr = htonl(ntohl(0x0100007F));

      struct sockaddr_in* address4 = (struct sockaddr_in*)address;

      const uint32_t a = ntohl(localhost.sin_addr.s_addr);
      const uint32_t b = ntohl(address4->sin_addr.s_addr);
      
      if (a == b)
         return true;
   } 
   return false;
}

bool address_equal(struct sockaddr_storage* left, struct sockaddr_storage* right)
{
   if (left->ss_family != right->ss_family)
   {
      //printf_debug("%s: different family", __func__);
      return false;
   }

   if (left->ss_family == AF_INET)
   {
      struct sockaddr_in* lin = (void*)left, *rin = (void*)right;
      if (ntohl(lin->sin_addr.s_addr) != ntohl(rin->sin_addr.s_addr))
      {
         //printf_debug("%s: different address", __func__);
         return false;
      }
      if (ntohs(lin->sin_port) != ntohs(rin->sin_port))
      {
         //printf_debug("%s: different port", __func__);
         return false;
      }
   } 
   else if (left->ss_family == AF_INET6)
   {
      struct sockaddr_in6 *lin6 = (void*)left, *rin6 = (void*)right;
      int r = memcmp(lin6->sin6_addr.s6_addr, rin6->sin6_addr.s6_addr, sizeof(lin6->sin6_addr.s6_addr));
      if (r != 0)
         return false;

      if (ntohs(lin6->sin6_port) != ntohs(rin6->sin6_port))
         return false;
      if (lin6->sin6_flowinfo != rin6->sin6_flowinfo)
         return false;
      if (lin6->sin6_scope_id != rin6->sin6_scope_id)
         return false;
   }

   return true;
}

bool address_to_string(const struct sockaddr_storage* address, char* buffer, socklen_t length)
{
   switch (address->ss_family)
   {
      case AF_INET:
         inet_ntop(AF_INET, &((struct sockaddr_in*)address)->sin_addr, buffer, length );
      break;
      case AF_INET6:
         inet_ntop(AF_INET6, &((struct sockaddr_in6*)address)->sin6_addr, buffer, length );
      break;
      default:
         return false;
   }
   return true;
}

bool assign_address_port(struct sockaddr_storage* address, const uint16_t port)
{
    switch (address->ss_family)
   {
      case AF_INET:
         ((struct sockaddr_in*)address)->sin_port = htons(port);
      break;
      case AF_INET6:
         ((struct sockaddr_in6*)address)->sin6_port = htons(port);
      break;
      default:
         return false;
   }
   return true;
}

bool parse_network_address(const char* address, struct sockaddr_storage* socket_address)
{
   printf_debug("%s: parsing %s\n", __func__, address); // debug

   struct addrinfo hints;
   CLEAR(hints);
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_DGRAM;
   hints.ai_protocol = IPPROTO_UDP;
   //hints.ai_flags = AI_ADDRCONFIG | (is_server ? AI_PASSIVE : 0);

   // *addrinfo functionality requires POSIX extensions (__USE_XOPEN2K8)
   struct addrinfo* result;
   int ret = getaddrinfo(address, NULL, &hints, &result);
   if (ret != 0)
   {
      printf("getaddrinfo: %s\n", gai_strerror(ret));
      return false;
   }

   if (result == NULL)
   {
      printf_debug("%s: no suitable address found for %s\n", __func__, address);
      return false;
   }

   if (result->ai_family == AF_INET)
   {
      struct sockaddr_in* ipv4 = (struct sockaddr_in*)socket_address;
      memcpy(ipv4, result->ai_addr, sizeof(*ipv4));
   }
   else if (result->ai_family == AF_INET6)
   {
      struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)socket_address;
      memcpy(ipv6, result->ai_addr, sizeof(*ipv6));
   }

   freeaddrinfo(result);

   char text[256];
   address_to_string(socket_address, text, sizeof(text));
   printf_debug("%s: found address %s\n", __func__, text);
   return true;
}

typedef enum {
   VPNMode_None,
   VPNMode_Server,
   VPNMode_Client
} VPNMode;

// arguments passed to the program to customize the local peer
typedef struct {
   VPNMode mode;
   char interface[IF_NAMESIZE];
   struct sockaddr_storage address;
   struct sockaddr_storage tunnel_address;
   struct sockaddr_storage tunnel_netmask;
   uint16_t mtu;
   bool persistent;
   bool debug_mode;
} StartupOptions;