
#include "PostRequest.h"

#include <stdlib.h>
#include <time.h>
#include "base64.h"


enum
{
    MOBILE_AUTHENTICATION = 0,
    SMARTCARD_AUTHENTICATION = 1,
};

enum
{
    ENCODE_BASE64_AND_ESCAPE = 1,
    ESCAPE_ONLY              = 2,
};


size_t WriteCallback(char *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

PostRequest::PostRequest()
{
    curl = 0;
    postParameters = 0;
}

void PostRequest::Init()
{
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
}

void PostRequest::Cleanup()
{
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    curl = 0;
}

void PostRequest::PrepareAndPerform(char *pUrl)
{
    curl_easy_setopt(curl, CURLOPT_URL, pUrl);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postParameters);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    res = curl_easy_perform(curl);
}

void PostRequest::GenerateSessionID()
{
    sessionID = "";

    srand((unsigned int)time(NULL));

    char randomChar[SESSION_ID_LENGTH + 1] = {'\0'};

    for (int i = 0; i < SESSION_ID_LENGTH; i++)
    {
        switch (rand() % 3)
        {
            case 0:
                randomChar[i] = 48 + (rand() % 9);
                break;

            case 1:
                randomChar[i] = 65 + (rand() % 26);
                break;

            case 2:
                randomChar[i] = 97 + (rand() % 26);
                break;

            default:
                break;
        }
    }

    sessionID = std::string(randomChar);
}

std::string PostRequest::GetDataFromResponse(char *pKeyword, int options=0)
{
    std::string stripeBegining = response.substr(response.find(pKeyword), response.length() - response.find(pKeyword));
    std::string stripeEnd = stripeBegining.substr(stripeBegining.find("value"), stripeBegining.find(">") - stripeBegining.find("value"));
    std::string stripeRest = stripeEnd.substr(stripeEnd.find("\"") + 1, stripeEnd.rfind("\""));
    std::string match = stripeRest.substr(0, stripeRest.find("\""));

    if (options == ENCODE_BASE64_AND_ESCAPE)
    {
        match = base64_encode((unsigned char*)match.c_str(), (unsigned int)match.length());
        match = ReservedCharactersEscape(match);
    }
    else if (options == ESCAPE_ONLY)
    {
        match = ReservedCharactersEscape(match);
    }

    return match;
}

std::string PostRequest::ReservedCharactersEscape(std::string str)
{
    for (size_t i = 0; i < str.length(); i++)
    {
        if (str[i] == ' ') { str.erase(i, 1); str.insert(i, "%20"); }
        else if (str[i] == '"') { str.erase(i, 1); str.insert(i, "%22"); }
        else if (str[i] == '#') { str.erase(i, 1); str.insert(i, "%23"); }
        else if (str[i] == '$') { str.erase(i, 1); str.insert(i, "%24"); }
        else if (str[i] == '%') { str.erase(i, 1); str.insert(i, "%25"); }
        else if (str[i] == '&') { str.erase(i, 1); str.insert(i, "%26"); }
        else if (str[i] == '\'') { str.erase(i, 1); str.insert(i, "%27"); }
        else if (str[i] == '+') { str.erase(i, 1); str.insert(i, "%2B"); }
        else if (str[i] == ',') { str.erase(i, 1); str.insert(i, "%2C"); }
        else if (str[i] == '/') { str.erase(i, 1); str.insert(i, "%2F"); }
        else if (str[i] == ':') { str.erase(i, 1); str.insert(i, "%3A"); }
        else if (str[i] == ';') { str.erase(i, 1); str.insert(i, "%3B"); }
        else if (str[i] == '<') { str.erase(i, 1); str.insert(i, "%3C"); }
        else if (str[i] == '=') { str.erase(i, 1); str.insert(i, "%3D"); }
        else if (str[i] == '>') { str.erase(i, 1); str.insert(i, "%3E"); }
        else if (str[i] == '?') { str.erase(i, 1); str.insert(i, "%3F"); }
        else if (str[i] == '@') { str.erase(i, 1); str.insert(i, "%40"); }
        else if (str[i] == '[') { str.erase(i, 1); str.insert(i, "%5B"); }
        else if (str[i] == '\\') { str.erase(i, 1); str.insert(i, "%5C"); }
        else if (str[i] == ']') { str.erase(i, 1); str.insert(i, "%5D"); }
        else if (str[i] == '^') { str.erase(i, 1); str.insert(i, "%5E"); }
        else if (str[i] == '`') { str.erase(i, 1); str.insert(i, "%60"); }
        else if (str[i] == '{') { str.erase(i, 1); str.insert(i, "%7B"); }
        else if (str[i] == '|') { str.erase(i, 1); str.insert(i, "%7C"); }
        else if (str[i] == '}') { str.erase(i, 1); str.insert(i, "%7D"); }
        else if (str[i] == '~') { str.erase(i, 1); str.insert(i, "%7E"); }
    }

    return str;
}

int PostRequest::FirstStagePost(char *pUrl, std::string sUsername, int vResetMethod, std::string sID)
{
    Init();

    int status = POST_REQUEST_SUCCESS;

    GenerateSessionID();
    username = sUsername;

    postParameters = (char*)calloc(MAX_POST_DATA_SIZE, sizeof(char));

    if (vResetMethod == MOBILE_AUTHENTICATION)
    {
        resetMethod = "code";
        snprintf(postParameters, MAX_POST_DATA_SIZE, "id=%s&username=%s&resetMethod=%s&unknownpadding=0", sessionID.c_str(), username.c_str(), resetMethod.c_str());
    }
    else if (vResetMethod == SMARTCARD_AUTHENTICATION)
    {
        resetMethod = "spineauth";
        snprintf(postParameters, MAX_POST_DATA_SIZE, "id=%s&username=%s&resetMethod=%s&uid=%s&unknownpadding=0", sessionID.c_str(), username.c_str(),
                                                                                                                 resetMethod.c_str(), sID.c_str());
    }

    PrepareAndPerform(pUrl);

    if (res != CURLE_OK)
    {
        status = POST_REQUEST_CONNECTION_ERROR;
        //fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
    else if (response.find("User account could not be found") != std::string::npos)
    {
        status = POST_REQUEST_USERNAME_NOT_FOUND;
    }
    else if (response.find("Username and Smartcard does not match") != std::string::npos)
    {
        status = POST_REQUEST_USER_SC_NO_MATCH;
    }
    else if (response.find("Failed to get response from server in a timely manner") != std::string::npos)
    {
        status = POST_REQUEST_TIME_OUT;
    }
    else if (response.find("code_hash") != std::string::npos)
    {
        codeHash = GetDataFromResponse("code_hash", ESCAPE_ONLY);
    }
    else if (response.find("challenge") != std::string::npos)
    {
        challenge = GetDataFromResponse("challenge");
        decodedChallenge = base64_decode(challenge);

        if (response.find("activatesignature") != std::string::npos)
        {
            activateSignature = GetDataFromResponse("activatesignature", ENCODE_BASE64_AND_ESCAPE);
        }
        else
        {
            status = POST_REQUEST_GET_DATA_FAILED;
        }
    }
    else
    {
        status = POST_REQUEST_GET_DATA_FAILED;
    }

    response = "";
    free(postParameters);
    postParameters = 0;
    Cleanup();

    return status;
}

int PostRequest::SecondStageMPCPost(char *pUrl, std::string sAuthCode)
{
    Init();

    int status = POST_REQUEST_SUCCESS;

    authCode = sAuthCode;

    postParameters = (char*)calloc(MAX_POST_DATA_SIZE, sizeof(char));
    snprintf(postParameters, MAX_POST_DATA_SIZE, "code_hash=%s&id=%s&username=%s&code=%s&unknownpadding=0",
                                                codeHash.c_str(), sessionID.c_str(), username.c_str(), authCode.c_str());

    PrepareAndPerform(pUrl);

    if (res != CURLE_OK)
    {
        status = POST_REQUEST_CONNECTION_ERROR;
        //fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
    else if (response.find("The reset code supplied was incorrect") != std::string::npos)
    {
        status = POST_REQUEST_INCORRECT_AUTH_CODE;
    }
    else if (response.find("evidence") != std::string::npos)
    {
        evidence = GetDataFromResponse("evidence");
    }
    else
    {
        status = POST_REQUEST_GET_DATA_FAILED;
    }

    response = "";
    free(postParameters);
    postParameters = 0;
    Cleanup();

    return status;
}

int PostRequest::ThirdStageMPCPost(char *pUrl, std::string sPassword)
{
    Init();

    int status = POST_REQUEST_SUCCESS;

    password = ReservedCharactersEscape(sPassword);

    passwordConfirm = password;

    postParameters = (char*)calloc(MAX_POST_DATA_SIZE, sizeof(char));
    snprintf(postParameters, MAX_POST_DATA_SIZE, "evidence=%s&id=%s&username=%s&password=%s&password-confirm=%s&unlock=on&unknownpadding=0",
                                            evidence.c_str(), sessionID.c_str(), username.c_str(), password.c_str(), passwordConfirm.c_str());

    PrepareAndPerform(pUrl);

    if (res != CURLE_OK)
    {
        status = POST_REQUEST_CONNECTION_ERROR;
        //fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
    else if (response.find("The reset code supplied was incorrect") != std::string::npos)
    {
        status = POST_REQUEST_INCORRECT_AUTH_CODE;
    }
    else if (response.find("The account could not be reset due to an undetermined issue") != std::string::npos)
    {
        status = POST_REQUEST_BAD_PASSWORD;
    }

    response = "";
    free(postParameters);
    postParameters = 0;
    Cleanup();

    return status;
}

int PostRequest::SecondStageSCPost(char *pUrl, std::string sSmartcardID, BYTE *pSignedChallenge, DWORD signedChallengeLength, BYTE *pCertificate, DWORD certLength)
{
    Init();

    int status = POST_REQUEST_SUCCESS;

    std::string sSignature = base64_encode(pSignedChallenge, signedChallengeLength);
    std::string sCert = base64_encode(pCertificate, certLength);
    std::string sChallenge = base64_encode((unsigned char*)challenge.c_str(), (unsigned int)challenge.length());
    sSignature = ReservedCharactersEscape(sSignature);
    sCert = ReservedCharactersEscape(sCert);
    sChallenge = ReservedCharactersEscape(sChallenge);

    postParameters = (char*)calloc(MAX_POST_DATA_SIZE, sizeof(char));
    snprintf(postParameters, MAX_POST_DATA_SIZE, "id=%s&username=%s&uid=%s&signature=%s&cert=%s&challenge=%s&activatesignature=%s&unknownpadding=0",
                 sessionID.c_str(), username.c_str(), sSmartcardID.c_str(), sSignature.c_str(), sCert.c_str(), sChallenge.c_str(), activateSignature.c_str());

    PrepareAndPerform(pUrl);

    if (res != CURLE_OK)
    {
        status = POST_REQUEST_CONNECTION_ERROR;
        //fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
    else if (response.find("validation failed") != std::string::npos)
    {
        status = POST_REQUEST_VALIDATE_FAILED;
    }
    else if (response.find("bad request") != std::string::npos)
    {
        status = POST_REQUEST_BAD_REQUEST;
    }
    else if (response.find("sso_ticket") != std::string::npos)
    {
        sso_ticket = GetDataFromResponse("sso_ticket");

        if (response.find("sso_logout_url") != std::string::npos)
        {
            sso_logout_url = GetDataFromResponse("sso_logout_url");
        }
        else
        {
            status = POST_REQUEST_GET_DATA_FAILED;
        }
    }
    else
    {
        status = POST_REQUEST_GET_DATA_FAILED;
    }

    response = "";
    free(postParameters);
    postParameters = 0;
    Cleanup();

    return status;
}

int PostRequest::ThirdStageSCPost(char *pUrl, std::string sID, std::string sPassword)
{
    Init();

    int status = POST_REQUEST_SUCCESS;

    password = ReservedCharactersEscape(sPassword);

    passwordConfirm = password;

    postParameters = (char*)calloc(MAX_POST_DATA_SIZE, sizeof(char));
    snprintf(postParameters, MAX_POST_DATA_SIZE, "uid=%s&id=%s&username=%s&sso_ticket=%s&sso_logout_url=%s&password=%s&password-confirm=%s&unlock=on&unknownpadding=0",
                         sID.c_str(), sessionID.c_str(), username.c_str(), sso_ticket.c_str(), sso_logout_url.c_str(), password.c_str(), passwordConfirm.c_str());

    PrepareAndPerform(pUrl);

    if (res != CURLE_OK)
    {
        status = POST_REQUEST_CONNECTION_ERROR;
        //fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }
    else if (response.find("The account could not be reset due to an undetermined issue") != std::string::npos)
    {
        status = POST_REQUEST_BAD_PASSWORD;
    }

    response = "";
    free(postParameters);
    postParameters = 0;
    Cleanup();

    return status;
}

PostRequest::~PostRequest()
{
    curl = 0;
    postParameters = 0;
}