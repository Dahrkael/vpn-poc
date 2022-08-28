#include <unistd.h>
#include <getopt.h>

#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "common.h"

typedef enum {
   VPNMode_None,
   VPNMode_Server,
   VPNMode_Client
} VPNMode;

typedef struct {
   VPNMode mode;
   char interface[IF_NAMESIZE];
   struct sockaddr_storage address;
   struct sockaddr_storage tunnel_address;
   struct sockaddr_storage tunnel_netmask;
   bool persistent;
} StartupOptions;

void show_help(const char* executable)
{
   if (!executable)
      executable = "executable";

   printf("\nUsage: %s {-s [<bind address>] | -c <remote address>} [-a <tunnel address>] [-m <tunnel netmask>] [-i <tunnel interface>] [-p] [-h]\n", executable);
   printf("\t-s, --server\tstart the vpn in server mode. optionally specify the address to bind to (defaults to 0.0.0.0).\n");
   printf("\t-c, --connect\tstart the vpn in client mode. specify the remote server address to connect to.\n");
   printf("\t-a, --address\tspecify the address used for the tun device (server only).\n");
   printf("\t-n, --mask\tspecify the network mask used for the tun device (server only).\n");
   printf("\t-i, --interface\ttun device name to create or attach if it already exists. (max 15 characters).\n");
   printf("\t-p, --persist\tkeep the tun device after shutting down the vpn.\n");
}

bool parse_network_address(const char* address, const bool is_server, struct sockaddr_storage* socket_address)
{
   struct addrinfo hints;
   CLEAR(hints);
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_DGRAM;
   hints.ai_protocol = IPPROTO_UDP;
   //hints.ai_flags = AI_ADDRCONFIG | (is_server ? AI_PASSIVE : 0);
   struct addrinfo* result;
   int ret = getaddrinfo(address, NULL, &hints, &result);
   if (ret != 0)
   {
      printf("getaddrinfo: %s\n", gai_strerror(ret));
      return false;
   }

   freeaddrinfo(result);
   return true;
}

bool parse_startup_options(int argc, char** argv, StartupOptions* result)
{
   assert(argv);
   assert(result);

   const struct option long_options[] = 
   {
      {"server",     optional_argument,   0, 's'}, // server mode with optional bind address
      {"connect",    required_argument,   0, 'c'}, // client mode connecting to specified server address
      {"address",    required_argument,   0, 'a'}, // tunnel address
      {"mask",       required_argument,   0, 'm'}, // tunnel network mask
      {"interface",  required_argument,   0, 'i'}, // tun device to use
      {"persist",    no_argument,         0, 'p'}, // keep the set tun device 
      {0, 0, 0, 0}
   };
   const char* short_options = ":s::c:a:m:i:p";

   bool error = false;
   while(1)
   {
      opterr = 0; // avoid getopt printing to stderr itself
      int option_index = 0;
      int c = getopt_long(argc, argv, short_options, long_options, &option_index);
      if (c == -1)
         break;

      switch (c)
      {
         case 's':
            if(result->mode != VPNMode_None)
            {
               printf("server and client options are mutually exclusive. please specify only one.\n");
               error = true;
            }

            result->mode = VPNMode_Server;
            const char* address = optarg ? optarg : "0.0.0.0";
            if (!parse_network_address(address, true, &result->address))
            {
               printf("invalid bind address provided\n");
               error = true;
            }
            break;
         case 'c':
            if(result->mode != VPNMode_None)
            {
               printf("client and server options are mutually exclusive. please specify only one.\n");
               error = true;
            }

            result->mode = VPNMode_Client;
            if (!optarg || !parse_network_address(optarg, false, &result->address))
            {
               printf("invalid remote address provided\n");
               error = true;
            }
            break;
         case 'a':
            if (!parse_network_address(optarg, true, &result->tunnel_address))
            {
               printf("invalid tunnel address provided\n");
               error = true;
            }
            break;
         case 'm': // TODO netmask
            break;
         case 'i':
            if (optarg)
               strncpy(result->interface, optarg, IF_NAMESIZE);
            break;
         case 'p':
            if (optarg)
               result->persistent = true;
            break;
         default: // group options that show the help
         {
            switch(c)
            {
               case ':':
                  printf("missing argument for option %c\n", optopt);
                  break;
               case '?':
                  printf("unknown option %c\n", optopt);
                  break;
            }
            error = true;
            break;
         }
      }
   }

   if (optind < argc) 
   {
      printf("ignored parameters: ");
      while (optind < argc)
         printf("%s ", argv[optind++]);
      printf("\n");
   }

   return !error;
}

int main(int argc, char** argv)
{
   StartupOptions startup_options;
   CLEAR(startup_options);

   // show the help if not arguments are provided or if errors arise while parsing them
   if ( argc == 1 || !parse_startup_options(argc, argv, &startup_options))
   {
      show_help(argv[0]);
      return 0;
   }
   
   Tunnel tunnel;
   CLEAR(tunnel);

   if (!tunnel_open(&tunnel, startup_options.interface))
   {
      printf("failed to open a tunnel\n");
      return 0;
   }

   printf("tunnel open on interface %s\n", tunnel.if_name);

   while(1)
   {
      sleep(1);
   }

   return 0;
}