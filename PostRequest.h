#pragma once

#include <curl.h>
#include <string>


enum
{
    MAX_USERNAME_SZIE   = 64,
    MAX_AUTH_CODE_SIZE  = 32,
    MAX_PASSWORD_SIZE   = 64,
    SESSION_ID_LENGTH   = 12,
    MAX_POST_DATA_SIZE  = 8192,
};

enum
{
    POST_REQUEST_SUCCESS             = 0,
    POST_REQUEST_CONNECTION_ERROR    = 1,
    POST_REQUEST_USERNAME_NOT_FOUND  = 2,
    POST_REQUEST_INCORRECT_AUTH_CODE = 3,
    POST_REQUEST_BAD_PASSWORD        = 4,
    POST_REQUEST_TIME_OUT            = 5,
    POST_REQUEST_GET_DATA_FAILED     = 6,
    POST_REQUEST_VALIDATE_FAILED     = 7,
    POST_REQUEST_USER_SC_NO_MATCH    = 8,
    POST_REQUEST_BAD_REQUEST         = 9,
};


class PostRequest
{
    public:
        std::string         decodedChallenge;

        PostRequest();
        int FirstStagePost(char *pUrl, std::string sUusername, int vResetMethod, std::string sID);
        int SecondStageMPCPost(char *pUrl, std::string sAuthCode);
        int ThirdStageMPCPost(char *pUrl, std::string sPassword);
        int SecondStageSCPost(char *pUrl, std::string sSmartcardID, BYTE *pSignedChallenge, DWORD signedChallengeLength, BYTE *pCertificate, DWORD certLength);
        int ThirdStageSCPost(char *pUrl, std::string sID, std::string sPassword);
        ~PostRequest();

    private:
        CURL               *curl;
        CURLcode		    res;
        std::string		    sessionID;
        std::string		    username;
        std::string		    resetMethod;
        std::string		    codeHash;
        std::string		    authCode;
        std::string		    evidence;
        std::string         challenge;
        std::string         activateSignature;
        std::string         sso_ticket;
        std::string         sso_logout_url;
        std::string		    password;
        std::string		    passwordConfirm;
        std::string         response;
        char			   *postParameters;

        void Init();
        void Cleanup();
        void PrepareAndPerform(char *pUrl);
        void GenerateSessionID();
        std::string GetDataFromResponse(char *pKeyword, int options);
        std::string ReservedCharactersEscape(std::string str);
};
