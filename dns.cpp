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

#define DNS_DEBUG_LOG 1

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#ifdef DNS_DEBUG_LOG
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#endif

#include "dns.h"

DNS::DNSServer DNS::_defaultDNS[] =
{
    // it is not 1996 anymore, IPv6 comes first with fallback to IPv4
    {(char*)"2606:4700:4700::1111", true, true, 853},
    {(char*)"2606:4700:4700::1001", true, true, 853},
    {(char*)"1.1.1.1", false, true, 853},
    {(char*)"1.0.0.1", false, true, 853},

    // Quad9
    {(char*)"2620:fe::fe", true, true, 853},
    {(char*)"9.9.9.9", false, true, 853},

    // last resort: non-TLS request
    {(char*)"2606:4700:4700::1111", true, false, 53},
    {(char*)"2606:4700:4700::1001", true, false, 53},
    {(char*)"1.1.1.1", false, false, 53},
    {(char*)"1.0.0.1", false, false, 53},

    // the least favorable option in case everything else failed
    {(char*)"8.8.8.8", false, false, 53}
};

DNS::DNS()
{
    // we could've checked for default DNS resolver in /etc/resolv.conf
    // but it'll destroy the whole concept of this class.
    // setup default Authoritative DNS to Cloudflare's DNS over TLS and cut the middle man
    // [2606:4700:4700::1111]:853
    // 1.1.1.1:853
    //
    // Alternatives are:
    // Quad9 - not a truly 'non-tracking' DNS, but still better than local ISP's DNS
    // [2620:fe::fe]:853
    // 9.9.9.9:853

    dnsserver = nullptr;
    _port = 853;
    _ipv6 = true;
    _isSSL = true;
    _sock = DNS_SOCKET_BAD;
    _error = NoError;
    _canPrint = false;
}

DNS::IP4info* DNS::getipbyname (const char *host)
{
    DNS dns;

    dns._canPrint = false;

    dns._Acnt = 0;
    dns.request(host, A);
    dns.parse(dns._buf, dns._bufSize);

    IP4info *pi = new IP4info;
    pi->count = dns._Acnt;
    pi->addrs = new in_addr[dns._Acnt];

    for(int i = 0 ; i < dns._Acnt ; i ++)
        memcpy(&pi->addrs[i], &dns._A[i], sizeof(in_addr));

    return pi;
}

DNS::IP6info* DNS::getip6byname (const char *host)
{
    DNS dns;

    dns._canPrint = false;

    dns._AAAAcnt = 0;
    dns.request(host, AAAA);
    dns.parse(dns._buf, dns._bufSize);

    IP6info *pi = new IP6info;
    pi->count = dns._AAAAcnt;
    pi->addrs = new in6_addr[dns._AAAAcnt];

    for(int i = 0 ; i < dns._AAAAcnt ; i ++)
        memcpy(&pi->addrs[i], &dns._AAAA[i], sizeof(in6_addr));

    return pi;
}

void DNS::print(const char *host, RequestType req)
{
    _canPrint = true;

    request(host, req);
    parse(_buf, _bufSize);
}

void DNS::request(const char *host, RequestType req)
{
    // as per https://tools.ietf.org/html/rfc1035#section-4.2.2
    Question *q = NULL;

    if(!host)
    {
        _error = BadParam;
        return ;
    }

    // https://tools.ietf.org/html/rfc1035#section-4.1.1
    Header *dns = (Header *)&_buf[0];
    //dns->id = (unsigned short) htons(getpid()); // or can be used in case of async multi resolver
    dns->id = (unsigned short)0x24a1;
    dns->qr = 0;
    dns->opcode = 0;        // standard query
    dns->aa = 0;            // Not Authoritative
    dns->tc = 0;            // TCP messages are not truncated
    dns->rd = 1;
    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->qCount = htons(1);
    dns->ansCount = 0;
    dns->authCount = 0;
    dns->addCount = 0;

    uint8_t *qname =(uint8_t*)&_buf[sizeof(Header)];
    DNS::toDnsFormat(qname, host);

    // https://tools.ietf.org/html/rfc1035#section-4.1.2
    q = (Question*)&_buf[sizeof(Header) + strlen((const char*)qname) + 1];
    q->qclass = htons(1);
    q->qtype = htons(req);

    if(_sock != DNS_SOCKET_BAD)
    {
        _error = Busy;
        return ;
    }

    // TODO: connect to next one if failed
    if(!connect(2))
        return ;

    uint16_t headerSize = sizeof(Header) + (strlen((const char*)qname) + 1) + sizeof(Question);
    uint16_t headerSizeBE = htons(headerSize);
    int n;
    memcpy(&_buf[2], &_buf[0], headerSize);
    memcpy(&_buf[0], &headerSizeBE, 2);

    // 0020abcd01 00 00 01 00 00 00 00 00 00 0377777706676f6f676c6503636f6d 00 00 01 00 01
    if(_isSSL)
        n = SSL_write(_ssl, _buf, headerSize + 2);
    else
        n = send(_sock, _buf, headerSize + 2, MSG_NOSIGNAL);

    if (n <= 0)
    {
        if(_isSSL && SSL_get_error(_ssl, n) != SSL_ERROR_NONE)
            _error = SSLError;
        else
            _error = SendError;
        ::close(_sock);
        _sock = DNS_SOCKET_BAD;
        return ;
    }

    timeval tv;
    fd_set rd;
    FD_ZERO(&rd);
    FD_SET(_sock, &rd);
    tv.tv_sec = 0;
    // typically dns server responds within 10-90ms
    // ...just in case..
    tv.tv_usec = 5000 * 1000 * 1000;
    if (select((int)(_sock + 1), &rd, NULL, NULL, &tv) <= 0)
    {
        debug("Response timeout.");
        _error = Timeout;
        ::close(_sock);
        _sock = DNS_SOCKET_BAD;
        return ;
    }

    if(_isSSL)
    {
        n = SSL_read(_ssl, _buf, 2);
        headerSizeBE = *((uint16_t*)_buf);
        _bufSize = htons(headerSizeBE);
        n = SSL_read(_ssl, _buf, 65536);
    }
    else
    {
        n = recv(_sock, _buf, 2, 0);
        headerSizeBE = *((uint16_t*)_buf);
        _bufSize = htons(headerSizeBE);
        n = recv(_sock, _buf, 65536, 0);
    }

    if (n <= 0) {
        if(_isSSL && SSL_get_error(_ssl, n) != SSL_ERROR_NONE)
            _error = SSLError;
        else
            _error = RecvError;
        ::close(_sock);
        _sock = DNS_SOCKET_BAD;
        return ;
    }

    _error = NoError;
    close();

    return ;
}

#define R16S(data, idx) ((((uint8_t*)(data))[idx] << 8) + ((uint8_t*)(data))[idx + 1])

int DNS::skipName(uint8_t *ptr)
{
    uint8_t *p = ptr;
    while(p)
    {
        int dotLen = *p;
        if (dotLen < 0) return -1;
        if (dotLen == 0) return (int)(p - ptr + 1);
        p += dotLen + 1;
    }
    return -1;
}

int DNS::parseQuery(uint8_t *ptr, int cnt)
{
    uint8_t *p = ptr;
    while(cnt > 0)
    {
        // https://tools.ietf.org/html/rfc1035#section-4.1.2
        // QNAME + QTYPE + QCLASS
        // skip the name for now. we know the owner of the request
        int nameLen = skipName(p);
        if(nameLen <= 0)
            return -1;
        p += nameLen + sizeof(Question);
        cnt--;
    }
    return (p - ptr);
}

int DNS::parseAnswer(uint8_t *ptr, uint8_t *buffer, int cnt)
{
    int len = 0;
    int tmp = 0;
    while(cnt > 0)
    {
        Answer a;
        uint8_t *p = ptr + len;

        // https://tools.ietf.org/html/rfc1035#section-4.1.3
        a.nameOffset =  R16S(p, 0);
        a.type = R16S(p, 2);
        a._class = R16S(p, 4);
        a.ttl = (((uint32_t)R16S(p, 6)) << 16) | R16S(p, 8);
        a.len = R16S(p, 10);

        int nameOffset = a.nameOffset & 0x3fff;
        uint8_t *tt = readName(buffer + nameOffset, buffer, &tmp);
        debug("%s", tt);
        free(tt);

        if(a.type == A)
        {
            _A[_Acnt].s_addr = *((uint32_t *)(p + sizeof(Answer)));
            debug("\t%d\tA\t%s\n", a.ttl, inet_ntoa(_A[_Acnt]));
            _Acnt++;
        }
        else if(a.type == AAAA)
        {
            memcpy(&_AAAA[_AAAAcnt], p + sizeof(Answer), sizeof(in6_addr));
            char buf6[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &_AAAA[_AAAAcnt], buf6, sizeof(buf6));
            _AAAAcnt++;
            debug("\t%d\tAAAA\t%s\n", a.ttl, buf6);

        }
        else
        {
            const char *rr = "";
            // in case of MX record, p + sizeof(Answer)+1 is MX priority, but I don't need it now, skip
            if(a.type == MX)
                tt = readName(p + sizeof(Answer)+2, buffer, &tmp);
            else
                tt = readName(p + sizeof(Answer), buffer, &tmp);

            if(a.type == CNAME)
                rr = "CNAME";
            else if(a.type == NS)
                rr = "NS";
            else if(a.type == TXT)
                rr = "TXT";
            else if(a.type == MX)
                rr = "MX";
            else if(a.type == PTR)
                rr = "PTR";
            else
                rr = "???";

            debug("\t%d\t%s\t%s\n", a.ttl, rr, tt);
            free(tt);
        }

        len += sizeof(a) + a.len;
        cnt--;
    }

    return len;
}

void DNS::parse(uint8_t *buffer, int len)
{
    if(!buffer || !len || len < sizeof(Header))
        return;

    _header.id = R16S(buffer, 0);
    uint16_t flags = R16S(buffer, 2);
    _header.qCount = R16S(buffer, 4);
    _header.ansCount = R16S(buffer, 6);

    if(!flags & 0x8000)
        return; // this is not an answer

    // should I check flags here before parsing data?
    if(_header.ansCount <= 0 || _header.ansCount > 20)
    {
        _header.ansCount = 0;
        return;
    }

    int recordOffset = sizeof(Header);
    if(_header.qCount > 0)
    {
        // parse Queries. basically skip them
        int size = parseQuery(buffer + recordOffset, _header.qCount);
        if(size <= 0)
            return;
        recordOffset += size;
    }

    if(_header.ansCount > 0)
        recordOffset += parseAnswer(buffer + recordOffset, buffer, _header.ansCount);

    // the same with
    // Auth
    // Additional
}

DNS::Error DNS::error()
{
    return _error;
}

bool DNS::connect(int dnsIdx)
{
    int nDefDns = sizeof(_defaultDNS) / sizeof(DNSServer);

    const SSL_METHOD *client_meth;

    const char *srv = dnsserver;
    short port = _port;
    bool bIPv6 = _ipv6;

    if(dnsIdx == -1)
    {
        if(!dnsserver)
        {
            _error = BadParam;
            return false;
        }
    }
    else
    {
       if(dnsIdx >= nDefDns)
            return false;
        srv = _defaultDNS[dnsIdx].server;
        port = _defaultDNS[dnsIdx].port;
        bIPv6 = _defaultDNS[dnsIdx].ipv6;
        _isSSL = _defaultDNS[dnsIdx].ssl;
    }

    if(_isSSL)
    {
        client_meth = SSLv23_method();
        _sslCtx = SSL_CTX_new(client_meth);

        if(!_sslCtx)
        {
            debug("Error initializing SSL");
            _error = SSLInit;
            _sock = DNS_SOCKET_BAD;
            return false;
        }
    }

    sockaddr *serveraddr = nullptr;
    sockaddr_in ip4;
    sockaddr_in6 ip6;
    int sockSize = 0;
    if(bIPv6)
    {
        if((_sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP)) < 0)
        {
            debug("Cant open socket\n");
            return false;
        }

        memset(&ip6, 0, sizeof(sockaddr_in6));
        ip6.sin6_family = AF_INET6;
        ip6.sin6_port = htons(port);
        inet_pton(AF_INET6, srv, (void *)&ip6.sin6_addr.s6_addr);
        serveraddr = (sockaddr*)&ip6;
        sockSize = sizeof(sockaddr_in6);
    }
    else
    {
        if((_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
        {
            debug("Cant open socket\n");
            return false;
        }

        memset(&ip4, 0, sizeof(sockaddr_in));
        ip4.sin_family = AF_INET;
        ip4.sin_port = htons(port);
        ip4.sin_addr.s_addr = inet_addr(srv);
        serveraddr = (sockaddr*)&ip4;
        sockSize = sizeof(sockaddr_in);
    }

    if(::connect(_sock, (sockaddr *)serveraddr, sockSize) < 0)
    {
        debug("Connect Error");
        _error = ConnectError;
        close();
        return false;
    }

    if(_isSSL)
    {
        _ssl = SSL_new(_sslCtx);
        if(!_ssl)
        {
            debug("SSL Error");
            _error = SSLError;
            close();
            return false;
        }
        SSL_set_fd(_ssl, _sock);

        if(SSL_connect(_ssl) != 1)
        {
            debug("SSL Error");
            _error = SSLError;
            close();
            return false;
        }

        X509 *ssl_cert = SSL_get_peer_certificate(_ssl);
        if(ssl_cert)
        {
            char *line;
            line = X509_NAME_oneline(X509_get_subject_name(ssl_cert), 0, 0);
            debug("Certificate Subject: %s\n", line);
            free(line);
            line = X509_NAME_oneline(X509_get_issuer_name(ssl_cert), 0, 0);
            debug("Certificate Issuer: %s\n", line);
            free(line);
            ASN1_BIT_STRING *pubKey = X509_get0_pubkey_bitstr(ssl_cert);
            char *key = new char[pubKey->length*2 + 1];
            for(int i = 0 ; i < pubKey->length ; i ++)
                sprintf(&key[i*2], "%02X", pubKey->data[i]);
            key[pubKey->length*2] = 0;
            debug("Certificate Pub: %s\n", key);
            delete [] key;
        }
    }

    return true;
}

void DNS::close(void)
{
    if(_isSSL)
    {
        if(_ssl)
        {
            SSL_shutdown(_ssl);
            SSL_free(_ssl);
        }
        if(_sslCtx)
            SSL_CTX_free(_sslCtx);
    }

    ::close(_sock);
    _sock = DNS_SOCKET_BAD;
}


void DNS::toDnsFormat(uint8_t *dns, const char *host)
{
    if(!host || !dns)
        return;

    unsigned int i, t = 0;
    for(i = 0 ; i < strlen((char*)host) ; i++)
    {
        if(host[i]=='.')
        {
            *dns++ = i-t;
            for(;t<i;t++)
                *dns++=host[t];
            t++;
        }
    }
    if(host[strlen(host)-1] != '.')
    {
        *dns++ = i-t;
        for(;t<i;t++)
            *dns++=host[t];
    }
    *dns++='\0';
}

uint8_t* DNS::readName(uint8_t *data, uint8_t *src, int *size)
{
    uint8_t *name;
    uint32_t idx, offset;
    bool bMoved = false;

    *size = 1;
    name = (unsigned char*)malloc(256);
    memset(name, 0, 256);

    idx = 0;
    while(*data != 0)
    {
        if(*data >= 192)
        {
            offset = (*data) * 256 + *(data + 1) - 49152; //49152 = 11000000 00000000
            data = src + offset - 1;
            bMoved = true; //we have jumped to another section of the answer
        }
        else
            name[idx++] = *data;

        data ++;
        if(!bMoved)
            (*size) ++;
    }

    name[idx]='\0';
    if(bMoved)
        (*size) ++;

    int i;
    for(i = 0 ; i < (int)strlen((const char*)name) ; i++)
    {
        idx = name[i];
        for(int j = 0 ; j < (int)idx ; j++)
        {
            name[i] = name[i + 1];
            i++;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0';
    return name;
}

void DNS::debug(const char *format, ...)
{
    if(!_canPrint)
        return;
#ifdef DNS_DEBUG_LOG
    va_list args;

    va_start(args, format);
    vprintf(format, args);
    // vprintf(file, buffer, format, args);
    va_end(args);
#endif
}
