//test arguments
//d:/test_csr.csr

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <unistd.h>
#include <getopt.h>
#include <cstring>

#include <openssl/safestack.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

using namespace std;
#define prt(x) cout << x << endl
#define err(x) cerr << x << endl
#define vb(x)  if (verbose) prt(x)

void viewcsr_print_help()
{
    err("Usage:");
    err("<path> : CSR to view");
}

int main_viewcsr(int argc, char* argv[])
{   
    if (argc < 2) {
        viewcsr_print_help();
        return 1;
    }
    
    FILE *csr_f = fopen(argv[1], "r");
    X509_REQ *x;
    if (!(x = PEM_read_X509_REQ(csr_f, 0, 0, 0))) {
        fseek(csr_f, 0, SEEK_SET);
        if (!(x = d2i_X509_REQ_fp(csr_f, 0))) {
            err("Invalid CSR");
            return 2;
        }
    }
    X509_REQ_print_fp(stdout, x);
    
    return 0;
}

