#include "common.h"

#include <getopt.h>
#include <netinet/ip.h>

// port used by the VPN
const uint16_t SERVICE_PORT = 10980;

void show_help(const char* executable)
{
   if (!executable)
      executable = "executable";

   printf("\nUsage: %s {-s [<bind address>] | -c <remote address>} [-a <tunnel address>] [-m <tunnel netmask>] [-i <tunnel interface>] [-p] [-h]\n", executable);
   printf("\t-s, --server\tstart the vpn in server mode. optionally specify the address to bind to (defaults to 0.0.0.0)\n");
   printf("\t-c, --connect\tstart the vpn in client mode. specify the remote server address to connect to.\n");
   printf("\t-a, --address\tspecify the address block used for the tun device. (defaults to 10.9.8.0)\n");
   printf("\t-m, --mask\tspecify the network mask used for the tun device. (defaults to 255.255.255.0)\n");
   printf("\t-i, --interface\ttun device name to create or attach if it already exists. (max 15 characters)\n");
   printf("\t-p, --persist\tkeep the tun device after shutting down the vpn.\n");
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
      {"mtu",        required_argument,   0, 'l'}, // socket & tunnel mtu
      {"interface",  required_argument,   0, 'i'}, // tun device to use
      {"persist",    no_argument,         0, 'p'}, // keep the set tun device 
      {"debug",      no_argument,         0, 'd'}, // debug mode
      {0, 0, 0, 0}
   };
   const char* short_options = ":s::c:a:m:l:i:p";

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
            if (!parse_network_address(address, &result->address))
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
            if (!parse_network_address(optarg, &result->address))
            {
               printf("invalid remote address provided\n");
               error = true;
            }
            break;
         case 'a':
            if (!parse_network_address(optarg, &result->tunnel_address))
            {
               printf("invalid tunnel address provided\n");
               error = true;
            }
            break;
         case 'm':
          if (!parse_network_address(optarg, &result->tunnel_netmask))
            {
               printf("invalid tunnel address provided\n");
               error = true;
            }
            break;
         case 'l':
         {
            uint32_t mtu = atoi(optarg);
            if (mtu < 576)
            {
               printf("mtu has to be at least 576 bytes");
               error = true;
            }
            if (mtu > UINT16_MAX) 
            {
               printf("mtu cannot exceed %u bytes", UINT16_MAX);
               error = true;
            }
            result->mtu = (uint16_t)mtu;
            break;
         }
         case 'i':
               strncpy(result->interface, optarg, IF_NAMESIZE);
            break;
         case 'p':
               result->persistent = true;
            break;
         case 'd':
            result->debug_mode = true;
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

int debug_main(const StartupOptions* startup_options)
{
   StartupOptions options_server, options_client;
   CLEAR(options_server);
   CLEAR(options_client);

   // use the same MTU for full compatibility
   options_server.mtu = startup_options->mtu;
   options_client.mtu = options_server.mtu;

   // setup two compatible peers to run side-by-side locally
   Peer* client = peer_create(options_server.mtu);
   Peer* server = peer_create(options_client.mtu);
   if (!client ||  !server)
   return -1;

   options_server.mode = VPNMode_Server;
   options_client.mode = VPNMode_Client;

   // hardcode the interfaces to something meaningful
   strncpy(options_server.interface, "ddgs", IF_NAMESIZE-1);
   strncpy(options_client.interface, "ddgc", IF_NAMESIZE-1);

   // use different blocks to avoid conflicts (default network mask)
   parse_network_address("10.9.7.0", &options_server.tunnel_address);
   parse_network_address("10.9.6.0", &options_client.tunnel_address);

   // connect them through localhost
   parse_network_address("127.0.0.1", &options_server.address);
   parse_network_address("127.0.0.1", &options_client.address);

   assign_address_port(&options_server.address, SERVICE_PORT);
   assign_address_port(&options_client.address, SERVICE_PORT);

   if (!peer_initialize(server, &options_server))
      return -1;
   
   if (!peer_initialize(client, &options_client))
      return -1;

   printf("server peer ready using interface %s\n", server->tunnel.if_name);
   printf("client peer ready using interface %s\n", client->tunnel.if_name);

   if (!peer_connect(client, &options_client.address))
      return -1;

   peer_enable(server, true);
   peer_enable(client, true);

   while(true)
   {
      peer_service(server);
      peer_service(client);
   }

   return 0;
}

int main(int argc, char** argv)
{
   if (!check_tun_privileges() || !check_socket_privileges())
   {
      printf("this program needs root or NET_CAP_ADMIN privileges\n");
      return 0;
   }

   StartupOptions startup_options;
   CLEAR(startup_options);

   // show the help if not arguments are provided or if errors arise while parsing them
   if ( argc == 1 || !parse_startup_options(argc, argv, &startup_options))
   {
      show_help(argv[0]);
      return 0;
   }

   // divert execution to testing mode
   if (startup_options.debug_mode)
      return debug_main(&startup_options);

   // assign the service port to the selected address
   assign_address_port(&startup_options.address, SERVICE_PORT);

   // prepare the local peer
   printf("creating local peer in %s mode\n", startup_options.mode == VPNMode_Server ? "SERVER" : "CLIENT");
   Peer* local_peer = peer_create(startup_options.mtu);
   if (!local_peer)
   {
      printf("failed to create peer. not enough memory?");
      return -1;
   }

   if (!peer_initialize(local_peer, &startup_options))
   {
      printf("failed to initialize peer\n");
      peer_destroy(local_peer);
      return -1;
   }

   printf("local peer ready using interface %s\n", local_peer->tunnel.if_name);

   peer_connect(local_peer, &startup_options.address);
   // TEST activate the tunnel
   tunnel_up(&local_peer->tunnel);

   while(true)
   {
      peer_service(local_peer);
      sleep(1);
   }

   return 0;
}