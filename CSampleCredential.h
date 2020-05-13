//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// CSampleCredential is our implementation of ICredentialProviderCredential.
// ICredentialProviderCredential is what LogonUI uses to let a credential
// provider specify what a user tile looks like and then tell it what the
// user has entered into the tile.  ICredentialProviderCredential is also
// responsible for packaging up the users credentials into a buffer that
// LogonUI then sends on to LSA.

#pragma once

#include <windows.h>
#include <strsafe.h>
#include <shlguid.h>
#include <propkey.h>
#include "common.h"
#include "dll.h"
#include "resource.h"
#include "PostRequest.h"
#include <string>
#include "Smartcard.h"


class CSampleCredential : public ICredentialProviderCredential2, ICredentialProviderCredentialWithFieldOptions
{
public:
    // IUnknown
    IFACEMETHODIMP_(ULONG) AddRef()
    {
        return ++_cRef;
    }

    IFACEMETHODIMP_(ULONG) Release()
    {
        long cRef = --_cRef;
        if (!cRef)
        {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP QueryInterface(_In_ REFIID riid, _COM_Outptr_ void **ppv)
    {
        static const QITAB qit[] =
        {
            QITABENT(CSampleCredential, ICredentialProviderCredential), // IID_ICredentialProviderCredential
            QITABENT(CSampleCredential, ICredentialProviderCredential2), // IID_ICredentialProviderCredential2
            QITABENT(CSampleCredential, ICredentialProviderCredentialWithFieldOptions), //IID_ICredentialProviderCredentialWithFieldOptions
            {0},
        };
        return QISearch(this, qit, riid, ppv);
    }
public:
    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(_In_ ICredentialProviderCredentialEvents *pcpce);
    IFACEMETHODIMP UnAdvise();

    IFACEMETHODIMP SetSelected(_Out_ BOOL *pbAutoLogon);

	HRESULT ResetFieldValue(DWORD fieldID);

    IFACEMETHODIMP SetDeselected();

    IFACEMETHODIMP GetFieldState(DWORD dwFieldID,
        _Out_ CREDENTIAL_PROVIDER_FIELD_STATE *pcpfs,
        _Out_ CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE *pcpfis);

    IFACEMETHODIMP GetStringValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ PWSTR *ppwsz);
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldID, _Outptr_result_nullonfailure_ HBITMAP *phbmp);
    IFACEMETHODIMP GetCheckboxValue(DWORD, _Out_ BOOL *, _Outptr_result_nullonfailure_ PWSTR *);
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldID, _Out_ DWORD *pcItems, _Deref_out_range_(< , *pcItems) _Out_ DWORD *pdwSelectedItem);
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldID, DWORD dwItem, _Outptr_result_nullonfailure_ PWSTR *ppwszItem);
    IFACEMETHODIMP GetSubmitButtonValue(DWORD, _Out_ DWORD *);

    IFACEMETHODIMP SetStringValue(DWORD dwFieldID, _In_ PCWSTR pwz);
    IFACEMETHODIMP SetCheckboxValue(DWORD, BOOL);
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldID, DWORD dwSelectedItem);

    void GrantFocus();
    void SpawnMessageBox(LPCTSTR message, LPCTSTR caption);

    int UsernameFormatCheck(std::string sUsername);
    int Stage_1_Username_Check(PWSTR *username);
    int AuthCodeFormatCheck(std::string sAuthCode);
    int Stage_2_Auth_Code_Check(PWSTR *authCode);
    int PinFormatCheck(std::string sPin);
    int Stage_2_Pin_Check(PWSTR *pin);
    int PasswordFormatCheck(std::string sPassword);
    int Stage_3_Password_Check(PWSTR *password, PWSTR *passwordConfirm);

    void Stage_1_Wait(int status);
    void Stage_2_Wait(int status);
    void Stage_3_Wait(int status);

    void PostRequestErrorCheck(int *status);
    int Stage_1_PostRequest(PWSTR username, int vResetMethod);
    int Stage_2_PostRequest(PWSTR authCode, int vResetMethod);
    int Stage_3_PostRequest(PWSTR password, int vResetMethod);

    void SmartcardErrorCheck(int *status);
    int SmartcardInitialise();
    int SmartcardVerifyPin(PWSTR pin);
    int SmartcardSigning(std::string challenge);

    void Stage_1_2_States(CREDENTIAL_PROVIDER_FIELD_STATE state1, CREDENTIAL_PROVIDER_FIELD_STATE state);
    void Stage_2_3_States(CREDENTIAL_PROVIDER_FIELD_STATE state1, CREDENTIAL_PROVIDER_FIELD_STATE state);
    void Stage_3_1_States(CREDENTIAL_PROVIDER_FIELD_STATE state1, CREDENTIAL_PROVIDER_FIELD_STATE state2);

    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldID);

    IFACEMETHODIMP GetSerialization(_Out_ CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE *,
        _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION *, _Outptr_result_maybenull_ PWSTR *, _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *);
    IFACEMETHODIMP ReportResult(NTSTATUS, NTSTATUS, _Outptr_result_maybenull_ PWSTR *, _Out_ CREDENTIAL_PROVIDER_STATUS_ICON *);

    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(_Outptr_result_nullonfailure_ PWSTR *);

    // ICredentialProviderCredentialWithFieldOptions
    IFACEMETHODIMP GetFieldOptions(DWORD dwFieldID,
        _Out_ CREDENTIAL_PROVIDER_CREDENTIAL_FIELD_OPTIONS *pcpcfo);

public:
    HRESULT Initialize(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus,
        _In_ CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR const *rgcpfd,
        _In_ FIELD_STATE_PAIR const *rgfsp,
        _In_ ICredentialProviderUser *pcpUser);
    CSampleCredential();

private:

    virtual ~CSampleCredential();
    long                                    _cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO      _cpus;                                          // The usage scenario for which we were enumerated.
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR    _rgCredProvFieldDescriptors[SFI_NUM_FIELDS];    // An array holding the type and name of each field in the tile.
    FIELD_STATE_PAIR                        _rgFieldStatePairs[SFI_NUM_FIELDS];             // An array holding the state of each field in the tile.
    PWSTR                                   _rgFieldStrings[SFI_NUM_FIELDS];                // An array holding the string value of each field. This is different from the name of the field held in _rgCredProvFieldDescriptors.
    PWSTR                                   _pszUserSid;
    PWSTR                                   _pszQualifiedUserName;                          // The user name that's used to pack the authentication buffer
    ICredentialProviderCredentialEvents2*   _pCredProvCredentialEvents;                     // Used to update fields.
                                                                                            // CredentialEvents2 for Begin and EndFieldUpdates.
    DWORD                                   _dwComboIndex;                                  // Tracks the current index of our combobox.
    bool                                    _fShowControls;                                 // Tracks the state of our show/hide controls link.
    bool                                    _fIsLocalUser;                                  // If the cred prov is assosiating with a local user tile

    HWND                                    hwndHandle;

    PostRequest                             postRequest;
    Smartcard                               smartcard;
};
