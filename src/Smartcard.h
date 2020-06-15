#pragma once

#include <Winscard.h>
#pragma comment(lib, "Winscard.lib")
#include <string>


enum
{
    MAX_NAME_SIZE       = 256,
    MAX_PIN_SIZE        = 64,
    SMARTCARD_ID_LENGTH = 12,
};

enum
{
    SMARTCARD_SUCCESS       = 0,
    SMARTCARD_NO_READER     = 1,
    SMARTCARD_NO_CARD       = 2,
    SMARTCARD_READ_FAILED   = 3,
    SMARTCARD_CERT_FAILED   = 4,
    SMARTCARD_INCORRECT_PIN = 5,
};


class Smartcard
{
    public:
        std::string         sID;
        BYTE               *pCertificate;
        BYTE               *pSignedChallenge;
        DWORD               certificateSize;
        DWORD               signedChallengeSize;

        Smartcard();
        int Init(HWND hwndHandle);
        int VerifyPin(std::string sPin);
        int GetData();
        int SignChallenge(std::string challenge);
        ~Smartcard();

    private:
        HCRYPTPROV          hCryptoContext;
        PCCERT_CONTEXT      pCertContext;

        bool                cryptContextReleased;
        bool                certificateContextReleased;
        bool                certificateReleased;
        bool                signedChallengeReleased;

        std::string         GetID(wchar_t *wSubject);

        void                ReleaseCryptContext();
        void                ReleaseCertContext();
        void                ReleaseCert();
        void                ReleaseSignedChallenge();
};

