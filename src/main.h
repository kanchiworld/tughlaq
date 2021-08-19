// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_MAIN_H
#define BITCOIN_MAIN_H

#include <limits>
#include <list>

#include "sync.h"
#include "script.h"
#include "block.h"
#include "mempool.h"

class CWallet;
class CKeyItem;
class CReserveKey;

class CAddress;
class CInv;
class CRequestTracker;
class CNode;



#ifdef USE_UPNP
static const int fHaveUPnP = true;
#else
static const int fHaveUPnP = false;
#endif


extern CScript                           COINBASE_FLAGS;
extern CCriticalSection                  cs_main;
extern CBlockIndex*                      g_pindexGenesisBlock;
extern unsigned int                      g_nNodeLifespan;
extern int                               g_nBestHeight;
extern uint256                           g_nBestChainTrust;
extern uint256                           g_nBestInvalidTrust;
extern uint256                           g_hashBestChain;
extern CBlockIndex*                      g_pindexBest;
extern unsigned int                      g_nTransactionsUpdated;
extern uint64_t                          nLastBlockTx;
extern uint64_t                          nLastBlockSize;
extern int                               g_nCoinbaseMaturity;
extern const std::string                 strMessageMagic;
extern int64_t                           g_nTimeBestReceived;
extern CCriticalSection                  cs_setpwalletRegistered;
extern std::set<CWallet*>                setpwalletRegistered;
extern unsigned char                     g_pchMessageStart[4];
extern std::map<CInv, int64_t>           mapAlreadyAskedFor;
extern std::map<uint256, CBlockIndex*>   g_mapBlockIndex;

// Settings
extern int64_t        nTransactionFee;
extern int64_t        nReserveBalance;
extern int64_t        nMinimumInputValue;
extern bool           fUseFastIndex;

extern bool           fEnforceCanonical;

// Minimum disk space required - used in CheckDiskSpace()
static const uint64_t nMinDiskSpace = 52428800;

extern CTxMemPool g_mempool;

namespace Tughlaq
{
//              Blockchain functions
void            SetBestChain(const CBlockLocator& loc);
bool            Reorganize(CTxDB& txdb, CBlockIndex* pindexNew);


//              Wallet Functions
void            RegisterWallet(CWallet* pwalletIn);
void            UnregisterWallet(CWallet* pwalletIn);
void            SyncWithWallets(const CTransaction& tx, const CBlock* pblock = NULL, bool fUpdate = false, bool fConnect = true);
void            ResendWalletTransactions();
bool            GetWalletFile(CWallet* pwallet, std::string &strWalletFileOut);

//              PoW functions
bool            CheckProofOfWork(uint256 hash, unsigned int nBits);
int64_t         GetProofOfWorkReward(int64_t nFees, const CBlockIndex *pindex);
int64_t         calculateMinerReward(const CBlockIndex *pindex);
unsigned int    ComputeMinWork(unsigned int nBase, int64_t nTime);
int             GetBlockRatePerHour();
unsigned int    calculateBlocktime(const CBlockIndex *pindex);
unsigned int    GetNextTargetRequired(const CBlockIndex* pindexLast);

//              Block File functions
bool            LoadExternalBlockFile(FILE* fileIn);
FILE*           OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode="rb");
FILE*           AppendBlockFile(unsigned int& nFileRet);
void            PrintBlockTree();

//                 Transactions and  Block functions
void               UpdatedTransaction(const uint256& hashTx);
bool               GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock);
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex);
bool               LoadBlockIndex(bool fAllowNew);
uint256            WantedByOrphan(const CBlock* pblockOrphan);
CBlockIndex*       FindBlockByHeight(int nHeight);
int                GetNumBlocksOfPeers();
bool               ProcessBlock(CNode* pfrom, CBlock* pblock);

//                 State functions
bool               IsInitialBlockDownload();
std::string        GetWarnings(std::string strFor);
bool               CheckDiskSpace(uint64_t nAdditionalBytes=0);
void               InvalidChainFound(CBlockIndex* );

//                 Main workhorse functions
bool               ProcessMessages(CNode* pfrom);
bool               SendMessages(CNode* pto, bool fSendTrickle);

};

#endif
