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

#include "dns.h"

int main(int argc, char *argv[])
{
    DNS dns;

    SSL_library_init();
    SSL_load_error_strings();

    auto ip4 = DNS::getipbyname("atomminer.com");
    auto ip6 = DNS::getip6byname("atomminer.com");

    delete [] ip4->addrs;
    delete ip4;
    delete [] ip6->addrs;
    delete ip6;

    dns.print("atomminer.com", DNS::A);
    printf("\n");
    dns.print("atomminer.com", DNS::NS);
    printf("\n");
    dns.print("atomminer.com", DNS::AAAA);
    printf("\n");
    dns.print("atomminer.com", DNS::MX);
    printf("\n");
    dns.print("atomminer.com", DNS::TXT);
    
    return 0;
}
