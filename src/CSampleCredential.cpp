//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
//

#ifndef WIN32_NO_STATUS
#include <ntstatus.h>
#define WIN32_NO_STATUS
#endif
#include <unknwn.h>
#include "CSampleCredential.h"
#include "guid.h"


enum
{
    VALID_FORMAT   = 0,
    INVALID_FORMAT = 1,
};

enum
{
    START_WAIT = 0,
    STOP_WAIT  = 1,
};

enum
{
    MPC_AUTHENTICATION = 0,
    SC_AUTHENTICATION  = 1,
};

enum
{
    PASS_RESET_PROVIDER_SUCCESS = 0,
    PASS_RESET_PROVIDER_FAILURE = 1,
};

CSampleCredential::CSampleCredential() :
    _cRef(1),
    _pCredProvCredentialEvents(nullptr),
    _pszUserSid(nullptr),
    _pszQualifiedUserName(nullptr),
    _fIsLocalUser(false),
    _fShowControls(true),
    _dwComboIndex(0)
{
    DllAddRef();

    ZeroMemory(_rgCredProvFieldDescriptors, sizeof(_rgCredProvFieldDescriptors));
    ZeroMemory(_rgFieldStatePairs, sizeof(_rgFieldStatePairs));
    ZeroMemory(_rgFieldStrings, sizeof(_rgFieldStrings));
}

CSampleCredential::~CSampleCredential()
{
    if (_rgFieldStrings[SFI_PASSWORD])
    {
        size_t lenPassword = wcslen(_rgFieldStrings[SFI_PASSWORD]);
        SecureZeroMemory(_rgFieldStrings[SFI_PASSWORD], lenPassword * sizeof(*_rgFieldStrings[SFI_PASSWORD]));
    }
    for (int i = 0; i < ARRAYSIZE(_rgFieldStrings); i++)
    {
        CoTaskMemFree(_rgFieldStrings[i]);
        CoTaskMemFree(_rgCredProvFieldDescriptors[i].pszLabel);
    }
    CoTaskMemFree(_pszUserSid);
    CoTaskMemFree(_pszQualifiedUserName);
    DllRelease();
}


// Initializes one credential with the field information passed in.
// Set the value of the SFI_LARGE_TEXT field to pwzUsername.
HRESULT CSampleCredential::Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
    _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
    _In_ FIELD_STATE_PAIR const *rgfsp,
    _In_ ICredentialProviderUser *pcpUser)
{
    HRESULT hr = S_OK;
    _cpus = cpus;

    GUID guidProvider;
    pcpUser->GetProviderID(&guidProvider);
    _fIsLocalUser = (guidProvider == Identity_LocalUserProvider);

    // Copy the field descriptors for each field. This is useful if you want to vary the field
    // descriptors based on what Usage scenario the credential was created for.
    for (DWORD i = 0; SUCCEEDED(hr) && i < ARRAYSIZE(_rgCredProvFieldDescriptors); i++)
    {
        _rgFieldStatePairs[i] = rgfsp[i];
        hr = FieldDescriptorCopy(rgcpfd[i], &_rgCredProvFieldDescriptors[i]);
    }

    // Initialize the String value of all the fields.
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Password Reset", &_rgFieldStrings[SFI_TITLE_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_USERNAME]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Reset Method Combobox", &_rgFieldStrings[SFI_AUTH_METHODS]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Continue", &_rgFieldStrings[SFI_STAGE_1_2]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_AUTH_CODE]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_SC_PIN]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Verify", &_rgFieldStrings[SFI_STAGE_2_3]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"", &_rgFieldStrings[SFI_PASSWORD_CONFIRM]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Submit", &_rgFieldStrings[SFI_STAGE_3_4]);
    }
    if (SUCCEEDED(hr))
    {
        hr = SHStrDupW(L"Please wait", &_rgFieldStrings[SFI_WAIT_LABEL]);
    }
    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetStringValue(PKEY_Identity_QualifiedUserName, &_pszQualifiedUserName);
    }
    /*if (SUCCEEDED(hr))
    {
        PWSTR pszUserName;
        pcpUser->GetStringValue(PKEY_Identity_UserName, &pszUserName);
        if (pszUserName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"User Name: %s", pszUserName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_FULLNAME_TEXT]);
            CoTaskMemFree(pszUserName);
        }
        else
        {
            hr =  SHStrDupW(L"User Name is NULL", &_rgFieldStrings[SFI_FULLNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszDisplayName;
        pcpUser->GetStringValue(PKEY_Identity_DisplayName, &pszDisplayName);
        if (pszDisplayName != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Display Name: %s", pszDisplayName);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
            CoTaskMemFree(pszDisplayName);
        }
        else
        {
            hr = SHStrDupW(L"Display Name is NULL", &_rgFieldStrings[SFI_DISPLAYNAME_TEXT]);
        }
    }
    if (SUCCEEDED(hr))
    {
        PWSTR pszLogonStatus;
        pcpUser->GetStringValue(PKEY_Identity_LogonStatusString, &pszLogonStatus);
        if (pszLogonStatus != nullptr)
        {
            wchar_t szString[256];
            StringCchPrintf(szString, ARRAYSIZE(szString), L"Logon Status: %s", pszLogonStatus);
            hr = SHStrDupW(szString, &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
            CoTaskMemFree(pszLogonStatus);
        }
        else
        {
            hr = SHStrDupW(L"Logon Status is NULL", &_rgFieldStrings[SFI_LOGONSTATUS_TEXT]);
        }
    }*/

    if (SUCCEEDED(hr))
    {
        hr = pcpUser->GetSid(&_pszUserSid);
    }

    return hr;
}

// LogonUI calls this in order to give us a callback in case we need to notify it of anything.
HRESULT CSampleCredential::Advise(_In_ ICredentialProviderCredentialEvents *pcpce)
{
    if (_pCredProvCredentialEvents != nullptr)
    {
        _pCredProvCredentialEvents->Release();
    }
    return pcpce->QueryInterface(IID_PPV_ARGS(&_pCredProvCredentialEvents));
}

// LogonUI calls this to tell us to release the callback.
HRESULT CSampleCredential::UnAdvise()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->Release();
    }
    _pCredProvCredentialEvents = nullptr;
    return S_OK;
}

// LogonUI calls this function when our tile is selected (zoomed)
// If you simply want fields to show/hide based on the selected state,
// there's no need to do anything here - you can set that up in the
// field definitions. But if you want to do something
// more complicated, like change the contents of a field when the tile is
// selected, you would do it here.
HRESULT CSampleCredential::SetSelected(_Out_ BOOL *pbAutoLogon)
{
    *pbAutoLogon = FALSE;
    return S_OK;
}

HRESULT CSampleCredential::ResetFieldValue(DWORD fieldID)
{
	HRESULT hr = S_OK;

	if (_rgFieldStrings[fieldID])
	{
		size_t lenFieldValue = wcslen(_rgFieldStrings[fieldID]);
		SecureZeroMemory(_rgFieldStrings[fieldID], lenFieldValue * sizeof(*_rgFieldStrings[fieldID]));

		CoTaskMemFree(_rgFieldStrings[fieldID]);
		hr = SHStrDupW(L"", &_rgFieldStrings[fieldID]);

		if (SUCCEEDED(hr) && _pCredProvCredentialEvents)
		{
			_pCredProvCredentialEvents->SetFieldString(this, fieldID, _rgFieldStrings[fieldID]);
		}
	}

	return hr;
}

// Similarly to SetSelected, LogonUI calls this when your tile was selected
// and now no longer is. The most common thing to do here (which we do below)
// is to clear out the password field.
HRESULT CSampleCredential::SetDeselected()
{
    HRESULT hr = S_OK;

	hr = ResetFieldValue(SFI_USERNAME);
	if (SUCCEEDED(hr))
	{
		hr = ResetFieldValue(SFI_AUTH_CODE);
	}
	if (SUCCEEDED(hr))
	{
		hr = ResetFieldValue(SFI_SC_PIN);
	}
	if (SUCCEEDED(hr))
	{
		hr = ResetFieldValue(SFI_PASSWORD);
	}
	if (SUCCEEDED(hr))
	{
		hr = ResetFieldValue(SFI_PASSWORD_CONFIRM);
	}

    return hr;
}

// Get info for a particular field of a tile. Called by logonUI to get information
// to display the tile.
HRESULT CSampleCredential::GetFieldState(DWORD dwFieldID,
    _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
    _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis)
{
    HRESULT hr;

    // Validate our parameters.
    if ((dwFieldID < ARRAYSIZE(_rgFieldStatePairs)))
    {
        *pcpfs = _rgFieldStatePairs[dwFieldID].cpfs;
        *pcpfis = _rgFieldStatePairs[dwFieldID].cpfis;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }
    return hr;
}

// Sets ppwsz to the string value of the field at the index dwFieldID
HRESULT CSampleCredential::GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz)
{
    HRESULT hr;
    *ppwsz = nullptr;

    // Check to make sure dwFieldID is a legitimate index
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors))
    {
        // Make a copy of the string and return that. The caller
        // is responsible for freeing it.
        hr = SHStrDupW(_rgFieldStrings[dwFieldID], ppwsz);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Get the image to show in the user tile
HRESULT CSampleCredential::GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp)
{
    HRESULT hr;
    *phbmp = nullptr;

    if ((SFI_TILEIMAGE == dwFieldID))
    {
        HBITMAP hbmp = LoadBitmap(HINST_THISDLL, MAKEINTRESOURCE(IDB_TILE_IMAGE));
        if (hbmp != nullptr)
        {
            hr = S_OK;
            *phbmp = hbmp;
        }
        else
        {
            hr = HRESULT_FROM_WIN32(GetLastError());
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Sets pdwAdjacentTo to the index of the field the submit button should be
// adjacent to. We recommend that the submit button is placed next to the last
// field which the user is required to enter information in. Optional fields
// should be below the submit button.
HRESULT CSampleCredential::GetSubmitButtonValue(DWORD, _Out_ DWORD *)
{
    return S_OK;
}

// Sets the value of a field which can accept a string as a value.
// This is called on each keystroke when a user types into an edit field
HRESULT CSampleCredential::SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_EDIT_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft ||
            CPFT_PASSWORD_TEXT == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR *ppwszStored = &_rgFieldStrings[dwFieldID];
        CoTaskMemFree(*ppwszStored);
        hr = SHStrDupW(pwz, ppwszStored);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Returns whether a checkbox is checked or not as well as its label.
HRESULT CSampleCredential::GetCheckboxValue(DWORD, _Out_ BOOL *, _Outptr_result_nullonfailure_ PWSTR *)
{
    return S_OK;
}

// Sets whether the specified checkbox is checked or not.
HRESULT CSampleCredential::SetCheckboxValue(DWORD, BOOL)
{
    return S_OK;
}

// Returns the number of items to be included in the combobox (pcItems), as well as the
// currently selected item (pdwSelectedItem).
HRESULT CSampleCredential::GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(< , *pcItems) _Out_ DWORD *pdwSelectedItem)
{
    HRESULT hr;
    *pcItems = 0;
    *pdwSelectedItem = 0;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        *pcItems = ARRAYSIZE(s_rgComboBoxStrings);
        *pdwSelectedItem = 0;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called iteratively to fill the combobox with the string (ppwszItem) at index dwItem.
HRESULT CSampleCredential::GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem)
{
    HRESULT hr;
    *ppwszItem = nullptr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        hr = SHStrDupW(s_rgComboBoxStrings[dwItem], ppwszItem);
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Called when the user changes the selected item in the combobox.
HRESULT CSampleCredential::SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem)
{
    HRESULT hr;

    // Validate parameters.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMBOBOX == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        _dwComboIndex = dwSelectedItem;
        hr = S_OK;
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

void CSampleCredential::GrantFocus()
{
    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->OnCreatingWindow(&hwndHandle);
    }
}

void CSampleCredential::SpawnMessageBox(LPCTSTR message, LPCTSTR caption)
{
    //HWND hwndOwner = nullptr;

    if (_pCredProvCredentialEvents)
    {
        _pCredProvCredentialEvents->OnCreatingWindow(&hwndHandle);
    }

    ::MessageBox(hwndHandle, message, caption, 0);
}

int CharCompare(char *lhs, char *rhs, unsigned int length)
{
    int status = PASS_RESET_PROVIDER_SUCCESS;

    for (unsigned int i = 0; i < length; i++)
    {
        if (lhs[i] != rhs[i])
        {
            status = PASS_RESET_PROVIDER_FAILURE;
            break;
        }
    }

    return status;
}

int CSampleCredential::UsernameFormatCheck(std::string sUsername)
{
    int status = VALID_FORMAT;

    for (size_t i = 0; i < sUsername.length(); i++)
    {
        if (((sUsername.c_str()[i] > 90) || (sUsername.c_str()[i] < 65)) &&
            ((sUsername.c_str()[i] > 122) || (sUsername.c_str()[i] < 97)))
        {
            status = INVALID_FORMAT;
        }
    }

    return status;
}

int CSampleCredential::Stage_1_Username_Check(PWSTR *username)
{
    int status = PASS_RESET_PROVIDER_FAILURE;

    PWSTR empty = L"";

    GetStringValue(SFI_USERNAME, username);

    char cUsername[MAX_USERNAME_SZIE] = {'\0'};
    snprintf(cUsername, MAX_USERNAME_SZIE, "%ws", *username);

    std::string sUsername(cUsername);

    if (**username == *empty)
    {
        SpawnMessageBox(L"Username cannot be empty.", L"Error");
    }
    else if (sUsername.length() < 3)
    {
        SpawnMessageBox(L"Username must be at least 3 characters long.", L"Error");
    }
    else if (UsernameFormatCheck(sUsername) != VALID_FORMAT)
    {
        SpawnMessageBox(L"Username contain letters only.", L"Error");
    }
    else
    {
        status = PASS_RESET_PROVIDER_SUCCESS;
    }

    return status;
}

int CSampleCredential::AuthCodeFormatCheck(std::string sAuthCode)
{
    int status = VALID_FORMAT;

    int authCodeLength = 0;

    for (size_t i = 0; i < sAuthCode.length(); i++)
    {
        if (sAuthCode[i] != ' ')
        {
            if (authCodeLength < 2)
            {
                if (((sAuthCode.c_str()[i] > 90) || (sAuthCode.c_str()[i] < 65)) &&
                    ((sAuthCode.c_str()[i] > 122) || (sAuthCode.c_str()[i] < 97)))
                {
                    status = INVALID_FORMAT;
                }
            }
            else
            {
                if ((sAuthCode.c_str()[i] > 57) || (sAuthCode.c_str()[i] < 48))
                {
                    status = INVALID_FORMAT;
                }
            }

            authCodeLength++;
        }
    }

    return status;
}

int CSampleCredential::Stage_2_Auth_Code_Check(PWSTR *authCode)
{
    int status = PASS_RESET_PROVIDER_FAILURE;

    PWSTR empty = L"";

    GetStringValue(SFI_AUTH_CODE, authCode);

    char cAuthCode[MAX_AUTH_CODE_SIZE] = {'\0'};
    snprintf(cAuthCode, MAX_AUTH_CODE_SIZE, "%ws", *authCode);

    std::string sAuthCode(cAuthCode);

    int authCodeLength = 0;
    for (size_t i = 0; i < sAuthCode.length(); i++)
    {
        if (sAuthCode[i] != ' ')
        {
            authCodeLength++;
        }
    }

    if (**authCode == *empty)
    {
        SpawnMessageBox(L"Authentication code cannot be empty.", L"Error");
    }
    else if (authCodeLength != 8)
    {
        SpawnMessageBox(L"Authentication code should be exactly 8 characters long.\n\nYou do not need to enter the spaces or use upper case letters.", L"Error");
    }
    else if (AuthCodeFormatCheck(sAuthCode) != VALID_FORMAT)
    {
        SpawnMessageBox(L"Authentication code has 2 letters and 6 digits, eg AB 123 456.\n\nYou do not need to enter the spaces or use upper case letters.", L"Error");
    }
    else
    {
        status = PASS_RESET_PROVIDER_SUCCESS;
    }

    return status;
}

int CSampleCredential::PinFormatCheck(std::string sPin)
{
    int status = VALID_FORMAT;

    for (size_t i = 0; i < sPin.length(); i++)
    {
        if ((sPin.c_str()[i] > 57) || (sPin.c_str()[i] < 48))
        {
            status = INVALID_FORMAT;
        }
    }

    return status;
}

int CSampleCredential::Stage_2_Pin_Check(PWSTR *pin)
{
    int status = PASS_RESET_PROVIDER_FAILURE;

    PWSTR empty = L"";

    GetStringValue(SFI_SC_PIN, pin);

    char cPin[MAX_USERNAME_SZIE] = { '\0' };
    snprintf(cPin, MAX_USERNAME_SZIE, "%ws", *pin);

    std::string sPin(cPin);

    if (**pin == *empty)
    {
        SpawnMessageBox(L"Smartcard pin cannot be empty.", L"Error");
    }
    else if (sPin.length() < 4)
    {
        SpawnMessageBox(L"Smartcard pin must be at least 4 digits long.", L"Error");
    }
    else if (PinFormatCheck(sPin) != VALID_FORMAT)
    {
        SpawnMessageBox(L"Smartcard pin contain digits only.", L"Error");
    }
    else
    {
        status = PASS_RESET_PROVIDER_SUCCESS;
    }

    return status;
}

int CSampleCredential::PasswordFormatCheck(std::string sPassword)
{
    int status = VALID_FORMAT;

    bool upper = false;
    bool lower = false;
    bool digit = false;
    bool symbol = false;

    for (size_t i = 0; i < sPassword.length(); i++)
    {
        if ((sPassword.c_str()[i] <= 90) && (sPassword.c_str()[i] >= 65))        { upper = true; }
        else if ((sPassword.c_str()[i] <= 122) && (sPassword.c_str()[i] >= 97))  { lower = true; }
        else if ((sPassword.c_str()[i] <= 57) && (sPassword.c_str()[i] >= 48))   { digit = true; }
        else if ((sPassword.c_str()[i] <= 47) && (sPassword.c_str()[i] >= 32))   { symbol = true; }
        else if ((sPassword.c_str()[i] <= 64) && (sPassword.c_str()[i] >= 58))   { symbol = true; }
        else if ((sPassword.c_str()[i] <= 96) && (sPassword.c_str()[i] >= 91))   { symbol = true; }
        else if ((sPassword.c_str()[i] <= 126) && (sPassword.c_str()[i] >= 123)) { symbol = true; }
    }

    if (!upper || !lower || (!digit && !symbol))
    {
        status = INVALID_FORMAT;
    }

    return status;
}

int CSampleCredential::Stage_3_Password_Check(PWSTR *password, PWSTR *passwordConfirm)
{
    int status = PASS_RESET_PROVIDER_FAILURE;

    PWSTR empty = L"";

    GetStringValue(SFI_PASSWORD, password);
    GetStringValue(SFI_PASSWORD_CONFIRM, passwordConfirm);

    char cPassword[MAX_PASSWORD_SIZE] = {'\0'};
    char cPasswordConfirm[MAX_PASSWORD_SIZE] = {'\0'};

    snprintf(cPassword, MAX_PASSWORD_SIZE, "%ws", *password);
    snprintf(cPasswordConfirm, MAX_PASSWORD_SIZE, "%ws", *passwordConfirm);

    std::string sPassword(cPassword);

    if (**password == *empty || **passwordConfirm == *empty)
    {
        SpawnMessageBox(L"Passwords cannot be empty.", L"Error");
    }
    else if (CharCompare(cPassword, cPasswordConfirm, MAX_PASSWORD_SIZE) == PASS_RESET_PROVIDER_FAILURE)
    {
        SpawnMessageBox(L"Passwords does not match.", L"Error");
    }
    else if (sPassword.length() < 8)
    {
        SpawnMessageBox(L"Password must be at least 8 charcters long.", L"Error");
    }
    else if (PasswordFormatCheck(sPassword) != VALID_FORMAT)
    {
        SpawnMessageBox(L"Password must contain a mixture of upper case and lower case letters and numbers or symbols.", L"Error");
    }
    else
    {
        status = PASS_RESET_PROVIDER_SUCCESS;
    }

    return status;
}

void CSampleCredential::Stage_1_Wait(int status)
{
    CREDENTIAL_PROVIDER_FIELD_STATE state1 = CPFS_HIDDEN;
    CREDENTIAL_PROVIDER_FIELD_STATE state2 = CPFS_HIDDEN;

    if (status == START_WAIT)
    {
        state1 = CPFS_HIDDEN;
        state2 = CPFS_DISPLAY_IN_SELECTED_TILE;
    }
    else if (status == STOP_WAIT)
    {
        state1 = CPFS_DISPLAY_IN_SELECTED_TILE;
        state2 = CPFS_HIDDEN;
    }

    _pCredProvCredentialEvents->BeginFieldUpdates();
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_USERNAME, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_AUTH_METHODS, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_STAGE_1_2, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_WAIT_LABEL, state2);
    _pCredProvCredentialEvents->EndFieldUpdates();
}

void CSampleCredential::Stage_2_Wait(int status)
{
    CREDENTIAL_PROVIDER_FIELD_STATE state1 = CPFS_HIDDEN;
    CREDENTIAL_PROVIDER_FIELD_STATE state2 = CPFS_HIDDEN;

    if (status == START_WAIT)
    {
        state1 = CPFS_HIDDEN;
        state2 = CPFS_DISPLAY_IN_SELECTED_TILE;
    }
    else if (status == STOP_WAIT)
    {
        state1 = CPFS_DISPLAY_IN_SELECTED_TILE;
        state2 = CPFS_HIDDEN;
    }

    _pCredProvCredentialEvents->BeginFieldUpdates();
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_STAGE_1_2, state1);

    if (_dwComboIndex == MPC_AUTHENTICATION)
    {
        _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_AUTH_CODE, state1);
    }
    else if (_dwComboIndex == SC_AUTHENTICATION)
    {
        _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_SC_PIN, state1);
    }

    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_STAGE_2_3, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_WAIT_LABEL, state2);
    _pCredProvCredentialEvents->EndFieldUpdates();
}

void CSampleCredential::Stage_3_Wait(int status)
{
    CREDENTIAL_PROVIDER_FIELD_STATE state1 = CPFS_HIDDEN;
    CREDENTIAL_PROVIDER_FIELD_STATE state2 = CPFS_HIDDEN;

    if (status == START_WAIT)
    {
        state1 = CPFS_HIDDEN;
        state2 = CPFS_DISPLAY_IN_SELECTED_TILE;
    }
    else if (status == STOP_WAIT)
    {
        state1 = CPFS_DISPLAY_IN_SELECTED_TILE;
        state2 = CPFS_HIDDEN;
    }

    _pCredProvCredentialEvents->BeginFieldUpdates();
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_STAGE_2_3, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PASSWORD, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PASSWORD_CONFIRM, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_STAGE_3_4, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_WAIT_LABEL, state2);
    _pCredProvCredentialEvents->EndFieldUpdates();
}

void CSampleCredential::PostRequestErrorCheck(int *status)
{
    switch (*status)
    {
        case POST_REQUEST_SUCCESS:
            *status = PASS_RESET_PROVIDER_SUCCESS;
            break;

        case POST_REQUEST_CONNECTION_ERROR:
            SpawnMessageBox(L"Cannot connect to service.", L"Error");
            break;

        case POST_REQUEST_USERNAME_NOT_FOUND:
            SpawnMessageBox(L"Username not found.", L"Error");
            break;

        case POST_REQUEST_INCORRECT_AUTH_CODE:
            SpawnMessageBox(L"Incorrect authentication code.", L"Error");
            break;

        case POST_REQUEST_BAD_PASSWORD:
            SpawnMessageBox(L"Password must be at least 8 characters long, contain a mixture of upper case and lower case letters with numbers or symbols.", L"Error");
            break;

        case POST_REQUEST_TIME_OUT:
            SpawnMessageBox(L"Connection timed out.", L"Error");
            break;

        case POST_REQUEST_GET_DATA_FAILED:
            SpawnMessageBox(L"Failed to get data from server.", L"Error");
            break;

        case POST_REQUEST_VALIDATE_FAILED:
            SpawnMessageBox(L"Failed to validate Smartcard.", L"Error");
            break;

        case POST_REQUEST_USER_SC_NO_MATCH:
            SpawnMessageBox(L"Username and Smartcard does not match.", L"Error");
            break;

        case POST_REQUEST_BAD_REQUEST:
            SpawnMessageBox(L"Bad request.", L"Error");
            break;

        default:
            break;
    }
}

int CSampleCredential::Stage_1_PostRequest(PWSTR username, int vResetMethod)
{
    Stage_1_Wait(START_WAIT);

    int status = PASS_RESET_PROVIDER_FAILURE;
    
    char cUsername[MAX_USERNAME_SZIE] = {'\0'};
    snprintf(cUsername, MAX_USERNAME_SZIE, "%ws", username);

    std::string sUsername(cUsername);

    if (vResetMethod == MPC_AUTHENTICATION)
    {
        status = postRequest.FirstStagePost("http://127.0.0.1:5001/reset_method", sUsername, vResetMethod, "");
    }
    else if (vResetMethod == SC_AUTHENTICATION)
    {
        status = postRequest.FirstStagePost("http://127.0.0.1:5001/reset_method", sUsername, vResetMethod, smartcard.sID);
    }

    PostRequestErrorCheck(&status);

    Stage_1_Wait(STOP_WAIT);

    return status;
}

int CSampleCredential::Stage_2_PostRequest(PWSTR authCode, int vResetMethod)
{
    Stage_2_Wait(START_WAIT);

    int status = PASS_RESET_PROVIDER_FAILURE;

    if (vResetMethod == MPC_AUTHENTICATION)
    {
        char cAuthCode[MAX_AUTH_CODE_SIZE] = { '\0' };
        snprintf(cAuthCode, MAX_AUTH_CODE_SIZE, "%ws", authCode);

        std::string sAuthCode(cAuthCode);

        status = postRequest.SecondStageMPCPost("http://127.0.0.1:5001/code", sAuthCode);
    }
    else if (vResetMethod == SC_AUTHENTICATION)
    {
        status = postRequest.SecondStageSCPost("http://127.0.0.1:5001/spineverify", smartcard.sID, smartcard.pSignedChallenge,
                                               smartcard.signedChallengeSize, smartcard.pCertificate, smartcard.certificateSize);
    }

    PostRequestErrorCheck(&status);

    Stage_2_Wait(STOP_WAIT);

    return status;
}

int CSampleCredential::Stage_3_PostRequest(PWSTR password, int vResetMethod)
{
    Stage_3_Wait(START_WAIT);

    int status = PASS_RESET_PROVIDER_FAILURE;

    char cPassword[MAX_PASSWORD_SIZE] = {'\0'};
    snprintf(cPassword, MAX_PASSWORD_SIZE, "%ws", password);

    std::string sPassword(cPassword);

    if (vResetMethod == MPC_AUTHENTICATION)
    {
        status = postRequest.ThirdStageMPCPost("http://127.0.0.1:5001/reset", sPassword);
    }
    else if (vResetMethod == SC_AUTHENTICATION)
    {
        status = postRequest.ThirdStageSCPost("http://127.0.0.1:5001/resetwithsmartcard", smartcard.sID, sPassword);
    }

    PostRequestErrorCheck(&status);

    Stage_3_Wait(STOP_WAIT);

    return status;
}

void CSampleCredential::SmartcardErrorCheck(int *status)
{
    switch (*status)
    {
    case SMARTCARD_SUCCESS:
        *status = PASS_RESET_PROVIDER_SUCCESS;
        break;

    case SMARTCARD_NO_READER:
        SpawnMessageBox(L"No Smartcard reader detected.", L"Error");
        break;

    case SMARTCARD_NO_CARD:
        SpawnMessageBox(L"No Smartcard detected.", L"Error");
        break;

    case SMARTCARD_READ_FAILED:
        SpawnMessageBox(L"Failed to read from Smartcard.", L"Error");
        break;

    case SMARTCARD_CERT_FAILED:
        SpawnMessageBox(L"Failed to retrieve certificate from Smartcard.", L"Error");
        break;

    case SMARTCARD_INCORRECT_PIN:
        SpawnMessageBox(L"Incorrect pin.", L"Error");
        break;

    default:
        break;
    }
}

int CSampleCredential::SmartcardInitialise()
{
    Stage_1_Wait(START_WAIT);

    int status = PASS_RESET_PROVIDER_FAILURE;

    status = smartcard.Init(hwndHandle);
    SmartcardErrorCheck(&status);

    if (status == PASS_RESET_PROVIDER_SUCCESS)
    {
        status = smartcard.GetData();
        SmartcardErrorCheck(&status);
    }

    Stage_1_Wait(STOP_WAIT);

    return status;
}

int CSampleCredential::SmartcardVerifyPin(PWSTR pin)
{
    Stage_2_Wait(START_WAIT);

    int status = PASS_RESET_PROVIDER_FAILURE;

    char cPin[MAX_PIN_SIZE] = {'\0'};
    snprintf(cPin, MAX_PIN_SIZE, "%ws", pin);

    std::string sPin(cPin);

    status = smartcard.VerifyPin(sPin);
    SmartcardErrorCheck(&status);

    Stage_2_Wait(STOP_WAIT);

    return status;
}

int CSampleCredential::SmartcardSigning(std::string challenge)
{
    Stage_2_Wait(START_WAIT);

    int status = PASS_RESET_PROVIDER_FAILURE;

    status = smartcard.SignChallenge(challenge);
    SmartcardErrorCheck(&status);

    Stage_2_Wait(STOP_WAIT);

    return status;
}

void CSampleCredential::Stage_1_2_States(CREDENTIAL_PROVIDER_FIELD_STATE state1, CREDENTIAL_PROVIDER_FIELD_STATE state2)
{
    _pCredProvCredentialEvents->BeginFieldUpdates();
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_USERNAME, state2);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_AUTH_METHODS, state2);

    if (_dwComboIndex == MPC_AUTHENTICATION)
    {
        _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_AUTH_CODE, state1);
    }
    else if (_dwComboIndex == SC_AUTHENTICATION)
    {
        _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_SC_PIN, state1);
    }

    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_STAGE_2_3, state1);
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_USERNAME, L"");
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_AUTH_CODE, L"");
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_SC_PIN, L"");
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_STAGE_1_2, _fShowControls ? L"Back" : L"Continue");
    _pCredProvCredentialEvents->EndFieldUpdates();
    _fShowControls = !_fShowControls;
}

void CSampleCredential::Stage_2_3_States(CREDENTIAL_PROVIDER_FIELD_STATE state1, CREDENTIAL_PROVIDER_FIELD_STATE state2)
{
    _pCredProvCredentialEvents->BeginFieldUpdates();

    if (_dwComboIndex == MPC_AUTHENTICATION)
    {
        _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_AUTH_CODE, state1);
    }
    else if (_dwComboIndex == SC_AUTHENTICATION)
    {
        _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_SC_PIN, state1);
    }

    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_STAGE_1_2, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PASSWORD, state2);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PASSWORD_CONFIRM, state2);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_STAGE_3_4, state2);
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_STAGE_2_3, _fShowControls ? L"Verify" : L"Back");
    _pCredProvCredentialEvents->EndFieldUpdates();
    _fShowControls = !_fShowControls;
}

void CSampleCredential::Stage_3_1_States(CREDENTIAL_PROVIDER_FIELD_STATE state1, CREDENTIAL_PROVIDER_FIELD_STATE state2)
{
    _pCredProvCredentialEvents->BeginFieldUpdates();
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_USERNAME, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_AUTH_METHODS, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_STAGE_1_2, state1);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PASSWORD, state2);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_PASSWORD_CONFIRM, state2);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_STAGE_2_3, state2);
    _pCredProvCredentialEvents->SetFieldState(nullptr, SFI_STAGE_3_4, state2);
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_USERNAME, L"");
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_AUTH_CODE, L"");
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_SC_PIN, L"");
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_PASSWORD, L"");
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_PASSWORD_CONFIRM, L"");
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_STAGE_1_2, _fShowControls ? L"Continue" : L"Back");
    _pCredProvCredentialEvents->SetFieldString(nullptr, SFI_STAGE_2_3, _fShowControls ? L"Verify" : L"Back");
    _pCredProvCredentialEvents->EndFieldUpdates();
    //_fShowControls = !_fShowControls;
}

// Called when the user clicks a command link.
HRESULT CSampleCredential::CommandLinkClicked(DWORD dwFieldID)
{
    HRESULT hr = S_OK;

    // Validate parameter.
    if (dwFieldID < ARRAYSIZE(_rgCredProvFieldDescriptors) &&
        (CPFT_COMMAND_LINK == _rgCredProvFieldDescriptors[dwFieldID].cpft))
    {
        PWSTR username = L"";
        PWSTR authCode = L"";
		PWSTR pin      = L"";
        PWSTR password = L"";
        PWSTR passwordConfirm = L"";
        int reset_method = MPC_AUTHENTICATION;

        CREDENTIAL_PROVIDER_FIELD_STATE state1 = _fShowControls ? CPFS_DISPLAY_IN_SELECTED_TILE : CPFS_HIDDEN;
        CREDENTIAL_PROVIDER_FIELD_STATE state2 = _fShowControls ? CPFS_HIDDEN : CPFS_DISPLAY_IN_SELECTED_TILE;

        switch (dwFieldID)
        {
            case SFI_STAGE_1_2:
				if (_fShowControls)
				{
					if (Stage_1_Username_Check(&username) == PASS_RESET_PROVIDER_SUCCESS)
					{
						if (_dwComboIndex == MPC_AUTHENTICATION)
						{
							if (Stage_1_PostRequest(username, MPC_AUTHENTICATION) == PASS_RESET_PROVIDER_SUCCESS)
							{
								Stage_1_2_States(state1, state2);
							}
						}
						else if (_dwComboIndex == SC_AUTHENTICATION)
						{
                            GrantFocus();
                            if (SmartcardInitialise() == PASS_RESET_PROVIDER_SUCCESS)
							{
                                if (Stage_1_PostRequest(username, SC_AUTHENTICATION) == PASS_RESET_PROVIDER_SUCCESS)
                                {
                                    Stage_1_2_States(state1, state2);
                                }
							}
						}
					}
				}
				else if (!_fShowControls)
				{
					Stage_1_2_States(state1, state2);
				}

                break;

            case SFI_STAGE_2_3:
				if (!_fShowControls)
				{
					if (_dwComboIndex == MPC_AUTHENTICATION)
					{
                        if (Stage_2_Auth_Code_Check(&authCode) == PASS_RESET_PROVIDER_SUCCESS)
                        {
                            if (Stage_2_PostRequest(authCode, MPC_AUTHENTICATION) == PASS_RESET_PROVIDER_SUCCESS)
                            {
                                Stage_2_3_States(state1, state2);
                            }
                        }
					}
					else if (_dwComboIndex == SC_AUTHENTICATION)
					{
						if (Stage_2_Pin_Check(&pin) == PASS_RESET_PROVIDER_SUCCESS)
						{
							if (SmartcardVerifyPin(pin) == PASS_RESET_PROVIDER_SUCCESS)
							{
                                if (SmartcardSigning(postRequest.decodedChallenge) == PASS_RESET_PROVIDER_SUCCESS)
                                {
                                    if (Stage_2_PostRequest(L"", SC_AUTHENTICATION) == PASS_RESET_PROVIDER_SUCCESS)
                                    {
                                        Stage_2_3_States(state1, state2);
                                    }
                                    else
                                    {
                                        Stage_1_2_States(state1, state2);
                                    }
                                }
							}
						}
					}
				}
				else if (_fShowControls)
				{
					Stage_3_1_States(state1, state2);
				}

                break;

            case SFI_STAGE_3_4:
                if (_dwComboIndex == MPC_AUTHENTICATION)
                {
                    reset_method = MPC_AUTHENTICATION;
                }
                else if (_dwComboIndex == SC_AUTHENTICATION)
                {
                    reset_method = SC_AUTHENTICATION;
                }

                if (Stage_3_Password_Check(&password, &passwordConfirm) == PASS_RESET_PROVIDER_SUCCESS)
                {
                    if (Stage_3_PostRequest(password, reset_method) == PASS_RESET_PROVIDER_SUCCESS)
                    {
                        SpawnMessageBox(L"Password has been changed, you can now log in with your new password.", L"Success");
                        Stage_3_1_States(state1, state2);
                    }
                }

                break;

            default:
                hr = E_INVALIDARG;
                break;
        }
    }
    else
    {
        hr = E_INVALIDARG;
    }

    return hr;
}

// Collect the username and password into a serialized credential for the correct usage scenario
// (logon/unlock is what's demonstrated in this sample).  LogonUI then passes these credentials
// back to the system to log on.
HRESULT CSampleCredential::GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *, _Outptr_result_maybenull_ PWSTR *, _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *)
{
    return S_OK;
}

// ReportResult is completely optional.  Its purpose is to allow a credential to customize the string
// and the icon displayed in the case of a logon failure.  For example, we have chosen to
// customize the error shown in the case of bad username/password and in the case of the account
// being disabled.
HRESULT CSampleCredential::ReportResult(NTSTATUS, NTSTATUS, _Outptr_result_maybenull_ PWSTR *, _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *)
{
    return S_OK;
}

// Gets the SID of the user corresponding to the credential.
HRESULT CSampleCredential::GetUserSid(_Outptr_result_nullonfailure_ PWSTR *)
{
    return S_OK;
}

// GetFieldOptions to enable the password reveal button and touch keyboard auto-invoke in the password field.
HRESULT CSampleCredential::GetFieldOptions(DWORD dwFieldID,
    _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo)
{
    *pcpcfo = CPCFO_NONE;

    if (dwFieldID == SFI_PASSWORD)
    {
        *pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
    }
	else if (dwFieldID == SFI_PASSWORD_CONFIRM)
	{
		*pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
	}
	else if (dwFieldID == SFI_SC_PIN)
	{
		*pcpcfo = CPCFO_ENABLE_PASSWORD_REVEAL;
	}
    else if (dwFieldID == SFI_TILEIMAGE)
    {
        *pcpcfo = CPCFO_ENABLE_TOUCH_KEYBOARD_AUTO_INVOKE;
    }

    return S_OK;
}
