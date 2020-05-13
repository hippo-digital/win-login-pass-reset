
#include "Smartcard.h"

#include <Wincrypt.h>
#pragma comment(lib, "Scarddlg.lib")
#pragma comment(lib, "crypt32.lib")

#include <Cryptuiapi.h>
#pragma comment(lib, "Cryptui.lib")


#define ENCODING_TYPE  (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)


Smartcard::Smartcard()
{
    hCryptoContext = 0;
    pCertContext = 0;
    pCertificate = 0;
    pSignedChallenge = 0;
    certificateSize = 0;
    signedChallengeSize = 0;

    cryptContextReleased = true;
    certificateContextReleased = true;
    certificateReleased = true;
    signedChallengeReleased = true;
}

int Smartcard::Init(HWND hwndHandle)
{
    ReleaseCryptContext();

    int status = SCARD_S_SUCCESS;

    SCARDCONTEXT SCardContext = 0;

    status = SCardEstablishContext(SCARD_SCOPE_USER, 0, 0, &SCardContext);
    if (status != SCARD_S_SUCCESS)
    {
        return SMARTCARD_NO_READER;
    }

    WCHAR szReader[MAX_NAME_SIZE];
    WCHAR szCard[MAX_NAME_SIZE];
    OPENCARDNAME_EX dlgStruct;
    memset(&dlgStruct, 0, sizeof(dlgStruct));

    dlgStruct.dwStructSize = sizeof(dlgStruct);
    dlgStruct.hSCardContext = SCardContext;
    dlgStruct.dwFlags = SC_DLG_FORCE_UI;
    dlgStruct.lpstrRdr = szReader;
    dlgStruct.nMaxRdr = MAX_NAME_SIZE;
    dlgStruct.lpstrCard = szCard;
    dlgStruct.nMaxCard = MAX_NAME_SIZE;
    dlgStruct.lpstrTitle = L"Reader Selector";
    dlgStruct.hwndOwner = hwndHandle;

    status = SCardUIDlgSelectCard(&dlgStruct);
    if (status != SCARD_S_SUCCESS)
    {
        SCardReleaseContext(SCardContext);
        return SMARTCARD_NO_CARD;
    }

    WCHAR pProviderName[256];
    DWORD cchProvider = 256;

    status = SCardGetCardTypeProviderName(dlgStruct.hSCardContext, dlgStruct.lpstrCard, SCARD_PROVIDER_CSP, pProviderName, &cchProvider);
    if (status != SCARD_S_SUCCESS)
    {
        SCardReleaseContext(SCardContext);
        return SMARTCARD_READ_FAILED;
    }

    if (!CryptAcquireContext(&hCryptoContext, 0, pProviderName, PROV_RSA_FULL, 0))
    {
        SCardReleaseContext(SCardContext);
        return SMARTCARD_CERT_FAILED;
    }

    cryptContextReleased = false;
    SCardReleaseContext(SCardContext);

    return SMARTCARD_SUCCESS;
}

std::string Smartcard::GetID(wchar_t *wSubject)
{
    char cSubject[MAX_NAME_SIZE] = {'\0'};
    snprintf(cSubject, MAX_NAME_SIZE, "%ws", wSubject);

    std::string sSubject = std::string(cSubject);

    std::string numStr = "";

    for (size_t i = 0; i < sSubject.length(); i++)
    {
        if (sSubject.c_str()[i] >= 48 && sSubject.c_str()[i] <= 57)
        {
            numStr.append(&sSubject.c_str()[i], 1);
        }
        else if (numStr.length() < SMARTCARD_ID_LENGTH)
        {
            numStr = "";
        }
        else
        {
            return numStr;
        }
    }

    return numStr;
}

int Smartcard::GetData()
{
    ReleaseCertContext();
    ReleaseCert();

    HCRYPTKEY hKey = 0;

    if (!CryptGetUserKey(hCryptoContext, AT_SIGNATURE, &hKey))
    {
        if (!CryptGetUserKey(hCryptoContext, AT_KEYEXCHANGE, &hKey))
        {
            ReleaseCryptContext();
            return SMARTCARD_CERT_FAILED;
        }
    }

    if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, 0, &certificateSize, 0))
    {
        CryptDestroyKey(hKey);
        ReleaseCryptContext();
        return SMARTCARD_CERT_FAILED;
    }

    pCertificate = (BYTE*)calloc(certificateSize, sizeof(BYTE));
    certificateReleased = false;

    if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, pCertificate, &certificateSize, 0))
    {
        ReleaseCert();
        CryptDestroyKey(hKey);
        ReleaseCryptContext();
        return SMARTCARD_CERT_FAILED;
    }

    PCCERT_CONTEXT pTokenCertContext = 0;
    pTokenCertContext = CertCreateCertificateContext(ENCODING_TYPE, pCertificate, certificateSize);

    if (pTokenCertContext)
    {
        DWORD certSize = 0;
        if (!CryptGetProvParam(hCryptoContext, PP_USER_CERTSTORE, 0, &certSize, 0))
        {
            CertFreeCertificateContext(pTokenCertContext);
            ReleaseCert();
            CryptDestroyKey(hKey);
            ReleaseCryptContext();
            return SMARTCARD_CERT_FAILED;
        }

        HCERTSTORE hStoreHandle = 0;

        if (!CryptGetProvParam(hCryptoContext, PP_USER_CERTSTORE, (PBYTE)&hStoreHandle, &certSize, 0))
        {
            CertFreeCertificateContext(pTokenCertContext);
            ReleaseCert();
            CryptDestroyKey(hKey);
            ReleaseCryptContext();
            return SMARTCARD_CERT_FAILED;
        }

        CERT_INFO certInfo;
        memset(&certInfo, 0, sizeof(certInfo));
        certInfo.Issuer = pTokenCertContext->pCertInfo->Issuer;
        certInfo.SerialNumber = pTokenCertContext->pCertInfo->SerialNumber;
        pCertContext = CertGetSubjectCertificateFromStore(hStoreHandle, ENCODING_TYPE, &certInfo);

        if (!pCertContext)
        {
            CertCloseStore(hStoreHandle, 0);
            CertFreeCertificateContext(pTokenCertContext);
            ReleaseCert();
            CryptDestroyKey(hKey);
            certificateContextReleased = true;
            ReleaseCryptContext();
            return SMARTCARD_CERT_FAILED;
        }

        wchar_t wSubject[MAX_NAME_SIZE] = {'\0'};
        CertNameToStr(ENCODING_TYPE, &pCertContext->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, wSubject, MAX_NAME_SIZE);
        //size_t wIDSize = CertNameToStr(ENCODING_TYPE, &pCertContext->pCertInfo->Subject, CERT_SIMPLE_NAME_STR, wSubject, MAX_NAME_SIZE);

        sID = GetID(wSubject);
        if (sID == "")
        {
            CertCloseStore(hStoreHandle, 0);
            CertFreeCertificateContext(pTokenCertContext);
            ReleaseCert();
            CryptDestroyKey(hKey);
            ReleaseCertContext();
            ReleaseCryptContext();
            return SMARTCARD_CERT_FAILED;
        }

        certificateContextReleased = false;
        CertCloseStore(hStoreHandle, 0);
        CertFreeCertificateContext(pTokenCertContext);
    }
    else
    {
        ReleaseCert();
        CryptDestroyKey(hKey);
        ReleaseCryptContext();

        return SMARTCARD_CERT_FAILED;
    }

    CryptDestroyKey(hKey);

    return SMARTCARD_SUCCESS;
}

int Smartcard::VerifyPin(std::string sPin)
{
    if (!CryptSetProvParam(hCryptoContext, PP_KEYEXCHANGE_PIN, (BYTE*)sPin.c_str(), 0))
    {
        return SMARTCARD_INCORRECT_PIN;
    }

    ReleaseCryptContext();

    return SMARTCARD_SUCCESS;
}

int Smartcard::SignChallenge(std::string challenge)
{
    ReleaseSignedChallenge();

    const BYTE *ChallengeArray[] = { (BYTE*)challenge.c_str() };
    DWORD_PTR ChallengeSizeArray[1] = { (DWORD)challenge.length() };

    CRYPT_SIGN_MESSAGE_PARA SigParams;
    memset(&SigParams, 0, sizeof(SigParams));

    SigParams.cbSize = sizeof(SigParams);
    SigParams.dwMsgEncodingType = ENCODING_TYPE;
    SigParams.pSigningCert = pCertContext;
    char objid[] = szOID_OIWSEC_sha1;
    SigParams.HashAlgorithm.pszObjId = objid;
    SigParams.cMsgCert = 1;
    SigParams.rgpMsgCert = &pCertContext;

    if (!CryptSignMessage(&SigParams, FALSE, 1, ChallengeArray, (DWORD*)ChallengeSizeArray, 0, &signedChallengeSize))
    {
        return SMARTCARD_CERT_FAILED;
    }

    pSignedChallenge = (BYTE*)calloc(signedChallengeSize, sizeof(BYTE));
    signedChallengeReleased = false;

    if (!CryptSignMessage(&SigParams, FALSE, 1, ChallengeArray, (DWORD*)ChallengeSizeArray, pSignedChallenge, &signedChallengeSize))
    {
        ReleaseSignedChallenge();
        return SMARTCARD_CERT_FAILED;
    }

    ReleaseCertContext();

    return SMARTCARD_SUCCESS;
}

void Smartcard::ReleaseCryptContext()
{
    if (!cryptContextReleased)
    {
        CryptReleaseContext(hCryptoContext, 0);
        hCryptoContext = 0;
        cryptContextReleased = true;
    }
}

void Smartcard::ReleaseCertContext()
{
    if (!certificateContextReleased)
    {
        CertFreeCertificateContext(pCertContext);
        pCertContext = 0;
        certificateContextReleased = true;
    }
}

void Smartcard::ReleaseCert()
{
    if (!certificateReleased)
    {
        free(pCertificate);
        pCertificate = 0;
        certificateReleased = true;
    }
}

void Smartcard::ReleaseSignedChallenge()
{
    if (!signedChallengeReleased)
    {
        free(pSignedChallenge);
        pSignedChallenge = 0;
        signedChallengeReleased = true;
    }
}

Smartcard::~Smartcard()
{
    ReleaseCryptContext();
    ReleaseCertContext();
    ReleaseCert();
    ReleaseSignedChallenge();
}