//
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// This file contains some global variables that describe what our
// sample tile looks like.  For example, it defines what fields a tile has
// and which fields show in which states of LogonUI. This sample illustrates
// the use of each UI field type.

#pragma once
#include "helpers.h"

// The indexes of each of the fields in our credential provider's tiles. Note that we're
// using each of the nine available field types here.
enum SAMPLE_FIELD_ID
{
    SFI_TILEIMAGE         = 0,
    SFI_TITLE_LABEL       = 1,
    SFI_USERNAME          = 2,
    SFI_AUTH_METHODS      = 3,
    SFI_STAGE_1_2         = 4,
    SFI_AUTH_CODE         = 5,
    SFI_SC_PIN            = 6,
    SFI_STAGE_2_3         = 7,
    SFI_PASSWORD          = 8,
    SFI_PASSWORD_CONFIRM  = 9,
    SFI_STAGE_3_4         = 10,
    SFI_WAIT_LABEL        = 11,
    SFI_NUM_FIELDS        = 12,  // Note: if new fields are added, keep NUM_FIELDS last.  This is used as a count of the number of fields
};

// The first value indicates when the tile is displayed (selected, not selected)
// the second indicates things like whether the field is enabled, whether it has key focus, etc.
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// These two arrays are seperate because a credential provider might
// want to set up a credential with various combinations of field state pairs
// and field descriptors.

// The field state value indicates whether the field is displayed
// in the selected tile, the deselected tile, or both.
// The Field interactive state indicates when
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_BOTH,            CPFIS_NONE    },    // SFI_TILEIMAGE
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_TITLE_LABEL
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_FOCUSED },    // SFI_USERNAME
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_AUTH_METHODS
    { CPFS_DISPLAY_IN_SELECTED_TILE,   CPFIS_NONE    },    // SFI_STAGE_1_2
    { CPFS_HIDDEN,                     CPFIS_FOCUSED },    // SFI_AUTH_CODE
    { CPFS_HIDDEN,                     CPFIS_FOCUSED },    // SFI_SC_PIN
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_STAGE_2_3
    { CPFS_HIDDEN,                     CPFIS_FOCUSED },    // SFI_PASSWORD
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_PASSWORD_CONFIRM
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_PASSWORD_SUBMIT
    { CPFS_HIDDEN,                     CPFIS_NONE    },    // SFI_WAIT_LABEL
};

// Field descriptors for unlock and logon.
// The first field is the index of the field.
// The second is the type of the field.
// The third is the name of the field, NOT the value which will appear in the field.
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgCredProvFieldDescriptors[] =
{
    { SFI_TILEIMAGE,         CPFT_TILE_IMAGE,       L"Image",                      CPFG_CREDENTIAL_PROVIDER_LOGO  },
    { SFI_TITLE_LABEL,       CPFT_LARGE_TEXT,       L"Password Reset"                                             },
    { SFI_USERNAME,          CPFT_EDIT_TEXT,        L"Username"                                                   },
    { SFI_AUTH_METHODS,      CPFT_COMBOBOX,         L"Reset Method Combobox"                                      },
    { SFI_STAGE_1_2,         CPFT_COMMAND_LINK,     L"Continue"                                                   },
    { SFI_AUTH_CODE,         CPFT_EDIT_TEXT,        L"Authentication Code"                                        },
    { SFI_SC_PIN,            CPFT_PASSWORD_TEXT,    L"Smartcard pin"                                              },
    { SFI_STAGE_2_3,         CPFT_COMMAND_LINK,     L"Verify"                                                     },
    { SFI_PASSWORD,          CPFT_PASSWORD_TEXT,    L"Password"                                                   },
    { SFI_PASSWORD_CONFIRM,  CPFT_PASSWORD_TEXT,    L"Retype password"                                            },
    { SFI_STAGE_3_4,         CPFT_COMMAND_LINK,     L"Submit"                                                     },
    { SFI_WAIT_LABEL,        CPFT_LARGE_TEXT,       L"Please wait"                                                },
};

static const PWSTR s_rgComboBoxStrings[] =
{
    L"Mobile Phone Code",
    L"Smartcard",
};
