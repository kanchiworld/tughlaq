// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_NET_H
#define BITCOIN_NET_H

#include <deque>
#include <boost/array.hpp>
#include <boost/foreach.hpp>

#include <thread>

#ifndef WIN32
#include <arpa/inet.h>
#endif

#include "mruset.h"
#include "netbase.h"
#include "protocol.h"
#include "addrman.h"
#include "node.h"
#include "db.h"

using namespace std;

class CAlert;


/*
 * mbt: shouldnt need it. do the thread management in a better way
 */

/** Thread types */
enum threadId
{
    THREAD_SOCKETHANDLER,
    THREAD_OPENCONNECTIONS,
    THREAD_MESSAGEHANDLER,
    THREAD_RPCLISTENER,
    THREAD_UPNP,
    THREAD_DNSSEED,
    THREAD_ADDEDCONNECTIONS,
    THREAD_DUMPADDRESS,
    THREAD_RPCHANDLER,

    THREAD_MAX
};



class CTransaction;

class CHomeNode
{
private:

    struct LocalServiceInfo
    {
    int nScore;
    int nPort;
    };

    static CHomeNode *instance;

    static const int MAX_OUTBOUND_CONNECTIONS = 20;
    
    map<CNetAddr, LocalServiceInfo> mapLocalHost;
    CCriticalSection cs_mapLocalHost;
    
    std::vector<CNode*> vNodes;
    CCriticalSection cs_vNodes;
    
    std::map<CInv, CDataStream> mapRelay;
    std::deque<pair<int64_t, CInv> > vRelayExpiration;
    std::map<CInv, int64_t> mapAlreadyAskedFor;
    CCriticalSection cs_mapRelay;
    
    deque<string> vOneShots;
    CCriticalSection cs_vOneShots;
    
    set<CNetAddr> setservAddNodeAddresses;
    CCriticalSection cs_setservAddNodeAddresses;
    
    std::vector<SOCKET> vhListenSocket;
    
    bool vfReachable[NET_MAX] {};
    bool vfLimited[NET_MAX] {}; 
    
    CNode* pnodeLocalHost;
    CAddress addrSeenByPeer;
    uint64_t nLocalHostNonce ;
    
    CAddrMan addrman;
    
    CSemaphore *semOutbound ;

    std::thread m_nodeThreads[THREAD_MAX];

// DNS seeds
// Each pair gives a source name and a seed name.
// The first name is used as information source for addrman.
// The second name should resolve to a list of seed addresses.
    static const char *strDNSSeed[][2] ;

// Constructor is private, to prevent duplicate instance creation. Use static getHomeNode fn.
CHomeNode() :
addrSeenByPeer(CService("0.0.0.0", 0), nLocalServices)
{
    pnodeLocalHost = NULL;
    nLocalHostNonce = 0;
    //vfReachable[NET_MAX] = {};
    //vfLimited[NET_MAX] = {};
    semOutbound = NULL;
}

CNode* FindNode(std::string addrName);


void DumpAddresses();

inline void RelayInventory(const CInv& inv)
{
    // Put on lists to offer to the other nodes
    {
        LOCK(cs_vNodes);
        for(CNode* pnode : vNodes)
            pnode->PushInventory(inv);
    }
}

void RelayTransaction(const CTransaction& tx, const uint256& hash, const CDataStream& ss);

// used when scores of local addresses may have changed
// pushes better local address to peers
void AdvertizeLocal()
{
    LOCK(cs_vNodes);
    for(CNode* pnode : vNodes)
    {
        if (pnode->fSuccessfullyConnected)
        {
            CAddress addrLocal = GetLocalAddress(&pnode->addr);
            if (addrLocal.IsRoutable() && (CService)addrLocal != (CService)pnode->addrLocal)
            {
                pnode->PushAddress(addrLocal);
                pnode->addrLocal = addrLocal;
            }
        }
    }
}

bool IsLocal(const CService& addr);

void ProcessOneShot()
{
    string strDest;
    {
        LOCK(cs_vOneShots);
        if (vOneShots.empty())
            return;
        strDest = vOneShots.front();
        vOneShots.pop_front();
    }
    CAddress addr;
    CSemaphoreGrant grant(*semOutbound, true);
    if (grant)
    {
        if (!OpenNetworkConnection(addr, &grant, strDest.c_str(), true))
            AddOneShot(strDest);
    }
}

bool OpenNetworkConnection(const CAddress& addrConnect, CSemaphoreGrant *grantOutbound, const char *strDest, bool fOneShot);
void Discover();
//GetMyExternalIP calls GetMyExternalIP2
bool GetMyExternalIP(CNetAddr& ipRet);
bool GetMyExternalIP2(const CService& addrConnect, const char* pszGet, const char* pszKeyword, CNetAddr& ipRet);
CNode* FindNode(const CNetAddr& ip);
CNode* FindNode(const CService& ip);
CNode* ConnectNode(CAddress addrConnect, const char *strDest = NULL);
void CloseSockets();

#ifdef USE_UPNP
void ThreadMapPort();
#endif
void ThreadDNSAddressSeed();
void ThreadSocketHandler();
void ThreadDumpAddress();
void ThreadOpenConnections();
void ThreadMessageHandler();
void ThreadOpenAddedConnections();

public:

static boost::array<int, THREAD_MAX> vnThreadsRunning;
enum
{
    LOCAL_NONE,   // unknown
    LOCAL_IF,     // address a local interface listens on
    LOCAL_BIND,   // address explicit bound to
    LOCAL_UPNP,   // address reported by UPnP
    LOCAL_IRC,    // address reported by IRC (deprecated)
    LOCAL_HTTP,   // address reported by whatismyip.com and similar
    LOCAL_MANUAL, // address explicitly specified (-externalip=)

    LOCAL_MAX
};


static uint64_t nLocalServices;

static CHomeNode*  getHomeNode()
{
    if (!instance) instance = new CHomeNode();
    return instance;
}

CAddrMan& getAddrMan()
{
    return addrman;
}

void MapPort();

int getNumPeers()
{
    LOCK(cs_vNodes);
    return vNodes.size();
}

//    CCriticalSection& getPeerNodesLock()
//    {
//        return cs_vNodes;
//    }
//    
//    std::vector<CNode*>& getPeerNodes()
//    {
//        return vNodes;
//    }

void                           SetLimited(enum Network net, bool fLimited);
bool                           IsLimited(enum Network net);
bool                           IsLimited(const CNetAddr& addr);
bool                           AddLocal(const CService& addr, int nScore = LOCAL_NONE);
bool                           AddLocal(const CNetAddr& addr, int nScore = LOCAL_NONE);
void                           SetReachable(enum Network net, bool fFlag );
bool                           IsReachable(const CNetAddr &addr);
bool                           SeenLocal(const CService& addr);
bool                           GetLocal(CService &addr, const CNetAddr *paddrPeer );
CAddress                       GetLocalAddress(const CNetAddr *paddrPeer );
void                           RelayTransaction(const CTransaction& tx, const uint256& hash);
void                           AddOneShot(std::string strDest);
bool                           RecvLine(SOCKET hSocket, std::string& strLine);
void                           AddressCurrentlyConnected(const CService& addr);
unsigned short                 GetListenPort();
bool                           BindListenPort(const CService &bindAddr, std::string& strError=REF(std::string()));
bool                           StartNode();
bool                           StopNode();

bool                           pushMessage(CNode*, const CInv&);
void                           setAddrSeenByPeer(CAddress& addrMe) { addrSeenByPeer = addrMe; }
CAddress                       getAddrSeenByPeer() { return addrSeenByPeer ; }
uint64_t                       getLocalHostNonce() { return nLocalHostNonce; }
void                           relayAlert(CAlert& alert);
void                           getPeerNodesStatsCopy(std::vector<CNodeStats>& vstats); //Make sure to pass in an empty vector
void                           pushInventory(const CInv& inv);
void                           broadcastAddressRefresh(bool clearPrevAddrs);
void                           getMapMix(multimap<uint256, CNode*>& mapMix, uint64_t hashAddr);

inline int64_t getInvAskedForTime(const CInv& inv)
{ 
    return mapAlreadyAskedFor[inv];
}

inline void setInvAskedForTime(const CInv& inv, int64_t nNow)
{
    mapAlreadyAskedFor[inv] = nNow;
}


inline void eraseInvAskedForTime(const CInv& inv)
{
    mapAlreadyAskedFor.erase(inv);
}


~CHomeNode(); //Definition in net.cpp
};

#endif
