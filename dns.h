/*
 * AtomMiner DNS over TLS resolver
 * Copyright AtomMiner, 2018,
 * All Rights Reserved
 *
 * CONFIDENTIAL AND PROPRIETARY INFORMATION
 * WHICH IS THE PROPERTY OF ATOMMINER
 *
 *      Author: AtomMiner - null3128
 */

#ifndef DNS_H
#define DNS_H

#include <inttypes.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#if defined(WIN32) && !defined(__LWIP_OPT_H__) && !defined(LWIP_HDR_OPT_H)
typedef SOCKET socket_t;
#define DNS_SOCKET_BAD INVALID_SOCKET
#else
typedef int socket_t;
#define DNS_SOCKET_BAD -1
#endif

class DNS
{
public:
    typedef enum {
        NoError = 0,
        Timeout,
        SendError,
        RecvError,
        Busy,
        BadParam,
        SSLInit,
        ConnectError,
        SSLError,
    } Error;

    // https://tools.ietf.org/html/rfc1035#section-3.2.2
    // https://tools.ietf.org/html/rfc3596
    typedef enum {
        // am I missing any records that might be of any practical use?
        // NSEC/NSEC3 ?
        A = 1,
        AAAA = 28,
        CNAME = 5,
        MX = 15,
        NS = 2,
        PTR = 12,
        TXT = 16
        //CERT = 37   // do we need it here? anyway, RFC to follow would be https://tools.ietf.org/html/rfc4398
    } RequestType;

    // https://tools.ietf.org/html/rfc1035#section-4.1.1
    typedef struct
    {
        unsigned short id;          // identification number
        unsigned char rd :1;        // recursion desired
        unsigned char tc :1;        // truncated message
        unsigned char aa :1;        // authoritive answer
        unsigned char opcode :4;    // purpose of message
        unsigned char qr :1;        // query/response flag

        unsigned char rcode :4;     // response code
        unsigned char cd :1;        // checking disabled
        unsigned char ad :1;        // authenticated data
        unsigned char z :1;         // reserved
        unsigned char ra :1;        // recursion available

        unsigned short qCount;     // number of question entries
        unsigned short ansCount;   // number of answer entries
        unsigned short authCount;  // number of authority entries
        unsigned short addCount;   // number of resource entries
    } Header;

#pragma pack(push, 1) // don not align it!
    typedef struct
    {
        unsigned short qtype;
        unsigned short qclass;
    } Question;

    typedef struct
    {
        unsigned short nameOffset;
        unsigned short type;
        unsigned short _class; // bummer! 'class' is the keyword in c++
        unsigned int ttl;
        unsigned short len;
    } Answer;

    typedef struct
    {
        unsigned char *name;
        Question *ques;
    } Query;
#pragma pack(pop)

    typedef struct
    {
        uint32_t count;
        in_addr *addrs;
    } IP4info;

    typedef struct
    {
        uint32_t count;
        in6_addr *addrs;
    } IP6info;

public:
    DNS();

    // https://webmasters.stackexchange.com/a/12704
    static IP4info* getipbyname (const char *host);
    static IP6info* getip6byname (const char *host);

    // for testing
    void print(const char *host, RequestType req);

    Error error();

protected:
    void request(const char *host, RequestType req);

    bool connect(int dnsIdx = -1);
    void close(void);
    static void toDnsFormat(uint8_t *dns, const char *host);

    static int skipName(uint8_t *ptr);
    static int parseQuery(uint8_t *ptr, int cnt);
    int parseAnswer(uint8_t *ptr, uint8_t *buffer, int cnt);
    void parse(uint8_t *buffer, int len);

    // reads data in dns format (3www6google3com) from the header/answer section(s)
    // and returns it in usable way. ret string should be free'ed
    static uint8_t* readName(uint8_t *data, uint8_t *src, int *size);

    void debug(const char *format, ...);

protected:
    typedef struct {
        char *server;
        bool ipv6;
        bool ssl;
        uint16_t port;
    } DNSServer;

    // we won't read nore than 20 records anyway
    in_addr   _A[20];
    int       _Acnt;
    in6_addr  _AAAA[20];
    int       _AAAAcnt;

    uint8_t  _buf[0xffff];
    uint16_t _bufSize;

    Header   _header;

    static DNSServer _defaultDNS[];
    char        *dnsserver;
    uint16_t    _port;
    bool        _ipv6;
    bool        _isSSL;
    socket_t    _sock;

    SSL         *_ssl;
    SSL_CTX     *_sslCtx;

    bool        _canPrint;

    Error       _error;
};

#endif // DNS_H
