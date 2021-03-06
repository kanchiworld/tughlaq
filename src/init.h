// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include "wallet.h"

extern CWallet*          g_tughlaqWallet;
extern std::string       g_strWalletFileName;
void StartShutdown();
void Shutdown(void* parg);
bool AppInit();
std::string HelpMessage();
#ifdef QT_GUI
void RestartWallet(const char *parm, bool fOldParms = true);
#endif

#endif
