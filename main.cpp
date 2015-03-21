#include <iostream>
#include <string>
#include <list>
#include <cstdlib>
#include <unistd.h>
#include <getopt.h>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/err.h>

using namespace std;

list<string> SUBAPP_LIST;
#define DECLARE_SUBAPP(x) extern int main_##x(int argc, char* argv[]); \
    SUBAPP_LIST.push_back(#x);
#define RUN_SUBAPP(x) main_##x (argc - 1, argv + 1)

#define prt(x) cout << x << endl
#define err(x) cerr << x << endl

void print_help()
{
    err("Available tools:");
    for (auto i : SUBAPP_LIST) {
        err(i);
    }
}

int main(int argc, char* argv[])
{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    DECLARE_SUBAPP(gencsr)
    DECLARE_SUBAPP(viewcsr)
    DECLARE_SUBAPP(ca)
    
    if (argc < 2) {
        print_help();
        return 1;
    }
    
    if (!strcmp(argv[1],"gencsr")) {
        RUN_SUBAPP(gencsr);
    } else if(!strcmp(argv[1],"viewcsr")) {
        RUN_SUBAPP(viewcsr);
    } else if(!strcmp(argv[1],"ca")) {
        RUN_SUBAPP(ca);
    } else if(!strcmp(argv[1],"ca")) {
        
    } else {
        print_help();
        return 1;
    }
    
    return -1;
}

