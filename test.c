#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>

int main() {
    HCERTSTORE hStore = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = 0;
    DWORD dwKeySpec = 0;
    BOOL fCallerFreeProvOrNCryptKey = FALSE;

    // Open the certificate store
    hStore = CertOpenStore(
        CERT_STORE_PROV_SYSTEM,
        0,
        0,
        CERT_SYSTEM_STORE_CURRENT_USER,
        L"MY"
    );
    if (!hStore) {
        printf("Failed to open certificate store. Error: %ld\n", GetLastError());
        return 1;
    }

    // Find the certificate by its subject name
    pCertContext = CertFindCertificateInStore(
        hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        0,
        CERT_FIND_SUBJECT_STR,
        L"Your CA Certificate Subject Name",
        NULL
    );
    if (!pCertContext) {
        printf("Certificate not found. Error: %ld\n", GetLastError());
        CertCloseStore(hStore, 0);
        return 1;
    }

    // Get the private key associated with the certificate
    if (!CryptAcquireCertificatePrivateKey(
            pCertContext,
            0,
            NULL,
            &hCryptProvOrNCryptKey,
            &dwKeySpec,
            &fCallerFreeProvOrNCryptKey)) {
        printf("Failed to acquire private key. Error: %ld\n", GetLastError());
        CertFreeCertificateContext(pCertContext);
        CertCloseStore(hStore, 0);
        return 1;
    }

    printf("Successfully acquired the certificate and private key.\n");

    // Use the certificate and private key for your cryptographic operations here
    // ...

    // Clean up
    if (fCallerFreeProvOrNCryptKey) {
        if (dwKeySpec == CERT_NCRYPT_KEY_SPEC) {
            NCryptFreeObject(hCryptProvOrNCryptKey);
        } else {
            CryptReleaseContext(hCryptProvOrNCryptKey, 0);
        }
    }
    CertFreeCertificateContext(pCertContext);
    CertCloseStore(hStore, 0);

    return 0;
}
