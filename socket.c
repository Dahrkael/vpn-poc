#include "common.h"

// socket wrapper to simplify the BSD interface
// UDP is assumed right now

typedef struct {
    int fd;
} Socket;

typedef enum
{
	SR_Error  = -1,
	SR_Pending = 0,
	SR_Success = 1
} SocketResult;

bool socket_clear(Socket* socket)
{
    if (!socket)
        return false;

    memset(socket, 0, sizeof(Socket));
    socket->fd = -1;
    return true;
}

bool socket_is_valid(Socket* socket)
{
    return (socket && socket->fd != -1);
}

bool socket_open(Socket* sock, const bool ipV6, const bool nonblocking)
{  
    if (!sock)
        return false;
        
    int s = socket(ipV6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == -1)
    {
        print_errno(__func__, "error creating socket", errno);
        return false;
    }

	// old datagrams may arrive when reusing addresses
	int32_t reuse = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1)
    {
        print_errno(__func__, "error setting socket options", errno);
        // not fatal
    }

    if (nonblocking)
    {
        int32_t flags = fcntl(s, F_GETFL, 0);
        if (flags == -1)
        {
            print_errno(__func__, "error retrieving socket flags", errno);
            close(s);
            return false;
        }

        int32_t ret = fcntl(s, F_SETFL, flags | O_NONBLOCK); // flags & ~O_NONBLOCK
        if (ret == -1)
        {
            print_errno(__func__, "error setting socket nonblocking", errno);
            close(s);
            return false;
        }
    }

    // set the socket only if everything went fine
    if (sock->fd != -1)
        close(sock->fd);

    sock->fd = s;

    return true;
}

bool socket_close(Socket* socket)
{
    if (!socket_is_valid(socket))
        return false;

    if ( close(socket->fd) == -1)
    {
        print_errno(__func__, "error closing socket", errno);
        return false;
    }

    socket->fd = -1;
    return true;
}

bool socket_set_buffer_sizes(Socket* socket, const int32_t recv_size, const int32_t send_size)
{
    if (!socket_is_valid(socket))
        return false;

    socklen_t optlen = sizeof(int32_t);
    if (setsockopt(socket->fd, SOL_SOCKET, SO_RCVBUF, &recv_size, optlen) == -1)
    {
        print_errno(__func__, "error setting socket recv buffer size", errno);
        return false;
    }

     if (setsockopt(socket->fd, SOL_SOCKET, SO_SNDBUF, &send_size, optlen) == -1)
    {
        print_errno(__func__, "error setting socket send buffer size", errno);
        return false;
    }

    return true;
}

bool socket_set_mark(Socket* socket, const uint32_t mark)
{
    if (!socket_is_valid(socket))
        return false;

    if (setsockopt(socket->fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) == -1)
    {
        print_errno(__func__, "error setting socket firewall mark", errno);
        return false;
    }
    return true;
}

// connect only allows incoming/outgoing packets from/to the specified address
bool socket_connect(Socket* socket, const struct sockaddr_storage* address)
{
    if (!socket_is_valid(socket))
        return false;

    int32_t ret = connect(socket->fd, (struct sockaddr*)address, sizeof(*address));
    if (ret == -1)
    {
        int32_t error = errno;
        if (error == EISCONN || error ==  EAGAIN || error == EWOULDBLOCK)
            return true;

        if (error == EAFNOSUPPORT)
            printf("%s: tried to connect to an IPv6 using IPv4 or viceversa\n", __func__);
        else
            print_errno(__func__, "error trying to connect socket", error);
        return false;
    }

    return true; 
}

// bind allows incoming packets from unknown addresses
bool socket_bind(Socket* socket, const struct sockaddr_storage* address)
{
    if (!socket_is_valid(socket))
        return false;

    int32_t ret = bind(socket->fd, (struct sockaddr*)address, sizeof(*address));
    if (ret == -1)
    {
        print_errno(__func__, "error binding socket", errno);
        return false;
    }

    return true;
}

bool socket_disconnect(Socket* socket)
{
    if (!socket_is_valid(socket))
        return false;

    // connecting to an AF_UNSPEC family detaches the socket
    struct sockaddr dummy;
    dummy.sa_family = AF_UNSPEC;
    if (connect(socket->fd, &dummy, sizeof(dummy)) == -1)
    {
        print_errno(__func__, "error disconnecting socket", errno);
        return false;
    }

    return true;
}

SocketResult socket_receive(Socket* socket, uint8_t* buffer, uint32_t* length, struct sockaddr_storage* remote)
{
    if (!socket_is_valid(socket))
        return SR_Error;

    socklen_t remoteLength = sizeof(*remote);
    ssize_t received = recvfrom(socket->fd, buffer, *length, 0, (struct sockaddr*)remote, remote ? &remoteLength : NULL);
    if (received == -1)
    {
        int32_t error = errno;
        if (error == EAGAIN || error == EWOULDBLOCK)
            return SR_Pending;

        print_errno(__func__, "error reading from socket", error);
        return SR_Error;
    }

    *length = (uint32_t)received;
    return SR_Success;
}

SocketResult socket_send(Socket* socket, const uint8_t* buffer, uint32_t* length, const struct sockaddr_storage* remote)
{
    if (!socket_is_valid(socket))
        return SR_Error;
    
    ssize_t sent = sendto(socket->fd, buffer, *length, 0, (struct sockaddr*)remote, sizeof(*remote) );
    if (sent == -1)
    {
        int32_t error = errno;
        if (error == EAGAIN || error == EWOULDBLOCK)
            return SR_Pending;

        print_errno(__func__, "error writing to socket", error);
        if (error == EMSGSIZE) // this should be recoverable
            return SR_Error;
        return SR_Error;
    }

    *length = (uint32_t)sent;
    return SR_Success;
}

bool check_socket_privileges()
{
    Socket dummy;
    if (!socket_open(&dummy, false, true))
        return false;

    if (!socket_set_mark(&dummy, 0x1))
        return false;

    socket_close(&dummy);
    return true;
}