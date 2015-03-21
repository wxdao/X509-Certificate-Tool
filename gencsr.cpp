//test arguments
//gencsr -r "CN=*.gov.cn,emailAddress=admin@gov.cn,ST=Beijing,C=CN,localityName=Beijing,O=Web,OU=Security" -o d:/test_csr -v

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>
#include <unistd.h>
#include <getopt.h>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#endif

#include <openssl/safestack.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>

using namespace std;
#define prt(x) cout << x << endl
#define err(x) cerr << x << endl
#define vb(x)  if (verbose) prt(x)

string prv_file;
string csr_file;
string rdns;
string challenge;
bool verbose = false;

void gencsr_print_help()
{
    err("Usage:");
    err("--rdns ,-r <string>           : RDNs");
    err("--prv_file <path>             : Output private key file");
    err("--csr_file <path>             : Output csr key file");
    err("-o         <path>             : Output file prefix");
    err("--help, -h                    : Print this message");
    err("--challenge,-c                : Challenge key");
    err("--format   <DER/PEM(default)> : Set format()");
    err("--verbose,-v                  : Output file prefix");
}

int mkcsr()
{
    X509_REQ *x;
    EVP_PKEY *pk;
    EC_KEY *eckey;
    X509_NAME *name = NULL;
    X509_NAME_ENTRY *ne = NULL;
    X509_EXTENSION *ex = NULL;
    vb("Generating key");
    eckey = EC_KEY_new_by_curve_name(715);
    if (!eckey) {
        err("Unsupported");
        return 4;
    }
    if (!EC_KEY_generate_key(eckey))
    {
        err("Key generation failed");
        return 5;
    }
    if (verbose) {
        EC_KEY_print_fp(stdout, eckey, 0);
    }
    
    EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
    
    pk = EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY(pk, eckey);
    x = X509_REQ_new();
    X509_REQ_set_version(x, 0);
    X509_REQ_set_pubkey(x, pk);
    name = X509_REQ_get_subject_name(x);
    
    vector<string> rdn_items;
    char *p;
    p = strtok((char*)rdns.c_str(), ",");
    while (p) {
        rdn_items.push_back(p);
        p = strtok(NULL, ",");
    }
    for (auto item : rdn_items) {
        char *j = (char*)item.c_str();
        while (*(j++) == ' ');
        --j;
        p = strtok(j, "=");
        if (!p) {
            err("Undefined rdn");
            return 6;
        }
        string txt = p;
        if (!(!strcmp(p, "CN") || !strcmp(p, "C") || !strcmp(p, "O") || !strcmp(p, "OU") || !strcmp(p, "ST") ||
              !strcmp(p, "commonName") || !strcmp(p, "countryName") || !strcmp(p, "organizationName") || !strcmp(p, "organizationalUnitName") || !strcmp(p, "stateOrProvinceName") || 
              !strcmp(p, "localityName") || !strcmp(p, "emailAddress"))) {
            err("Undefined rdn : " << p);
            return 6;
        }
        p = strtok(NULL, "=");
        if (!p) {
            err("Undefined rdn");
            return 6;
        }
        X509_NAME_add_entry_by_txt(name, txt.c_str(), MBSTRING_ASC, (unsigned char*)p, -1, -1, 0);
    }
    
    if (!challenge.empty()) {
        X509_REQ_add1_attr_by_txt(x, "challengePassword", MBSTRING_ASC, (unsigned char*)challenge.c_str(), -1);
    }
    
    X509_REQ_sign(x, pk, EVP_sha384());
    if (verbose) {
        X509_REQ_print_fp(stdout, x);
    }
    FILE *csr_f = fopen(csr_file.c_str(), "wb");
    FILE *prv_f = fopen(prv_file.c_str(), "wb");
    
    PEM_write_X509_REQ(csr_f, x);
    PEM_write_PrivateKey(prv_f, pk, EVP_aes_256_cbc(), 0, 0, 0, 0);
    vb("Done");
    return 0;
}

char *covertToUpper(char *str){
    char *newstr, *p;
    p = newstr = strdup(str);
    while(*p++ = toupper(*p));

    return newstr;
}

int main_gencsr(int argc, char* argv[])
{   
    if (argc < 2) {
        gencsr_print_help();
        return 1;
    }
    
    const char *short_opts = "r:o:hvc:";
    struct option long_opts[] = {
    {"rdns", required_argument, NULL, 'r'},
    {"prv_out", required_argument, NULL, 270},
    {"csr_out", required_argument, NULL, 271},
    {"out", required_argument, NULL, 'o'},
    {"help", no_argument, NULL, 'h'},
    {"verbose", no_argument, NULL, 'v'},
    {"challenge", no_argument, NULL, 'c'},
};
    int c;
    char *_format;
    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != -1) {
        switch (c) {
        case 'r':
            rdns = optarg;
            break;
        case 'o':
            prv_file = string(optarg) + ".key";
            csr_file = string(optarg) + ".csr";
            break;
        case 270:
            prv_file = string(optarg) + ".key";
            break;
        case 271:
            csr_file = string(optarg) + ".csr";
            break;
        case 'h':
            gencsr_print_help();
            return 0;
            break;
        case 'v':
            verbose = true;
            break;
        case 'c':
            challenge = optarg;
            break;
        default:
            gencsr_print_help();
            return 1;
            break;
        }
    }
    
    if (prv_file.empty() || csr_file.empty()) {
        err("Output file unspecified");
        return 2;
    }
    
    if (rdns.empty()) {
        err("RDNs unspecified");
        return 2;
    }
    
    return mkcsr();
}

