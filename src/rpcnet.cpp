// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net.h"
#include "bitcoinrpc.h"
#include "alert.h"
#include "wallet.h"
#include "db.h"
#include "walletdb.h"

using namespace json_spirit;
using namespace std;

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

Value getconnectioncount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getconnectioncount\n"
            "Returns the number of connections to other nodes.");

    return (int)CHomeNode::getHomeNode()->getNumPeers();
}

static void CopyNodeStats(std::vector<CNodeStats>& vstats)
{
    vstats.clear();
    CHomeNode::getHomeNode()->getPeerNodesStatsCopy(vstats);
}

Value getpeerinfo(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getpeerinfo\n"
            "Returns data about each connected network node.");

    vector<CNodeStats> vstats;
    CopyNodeStats(vstats);

    Array ret;

    for(const CNodeStats& stats : vstats)
    {
        Object obj;

        obj.push_back(Pair("addr", stats.addrName));
        obj.push_back(Pair("services", strprintf("%08" PRIx64 , stats.nServices)));
        obj.push_back(Pair("lastsend", (boost::int64_t)stats.nLastSend));
        obj.push_back(Pair("lastrecv", (boost::int64_t)stats.nLastRecv));
        obj.push_back(Pair("conntime", (boost::int64_t)stats.nTimeConnected));
        obj.push_back(Pair("version", stats.nVersion));
        obj.push_back(Pair("subver", stats.strSubVer));
        obj.push_back(Pair("inbound", stats.fInbound));
        obj.push_back(Pair("startingheight", stats.nStartingHeight));
        obj.push_back(Pair("banscore", stats.nMisbehavior));

        ret.push_back(obj);
    }

    return ret;
}
 
// ppcoin: send alert.  
// There is a known deadlock situation with ThreadMessageHandler
// ThreadMessageHandler: holds cs_vSend and acquiring cs_main in SendMessages()
// ThreadRPCServer: holds cs_main and acquiring cs_vSend in alert.RelayTo()/PushMessage()/BeginMessage()
Value sendalert(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 7)
        throw runtime_error(
            "sendalert <message> <privatekey> <minver> <maxver> <subver> <priority> <id> [cancelupto]\n"
            "<message> is the alert text message\n"
            "<privatekey> is hex string of alert master private key\n"
            "<minver> is the minimum applicable internal client version\n"
            "<maxver> is the maximum applicable internal client version\n"
            "<subver> is the string client version /BlackPanther:0.0.0/\n"
            "<priority> is integer priority number\n"
            "<id> is the alert id\n"
            "[cancelupto] cancels all alert id's up to this number\n"
            "Returns true or false.");

    CAlert alert;
    CKey key;

    alert.strStatusBar = params[0].get_str();
    alert.nMinVer = params[2].get_int();
    alert.nMaxVer = params[3].get_int();
    std::string strSetSubVer = params[4].get_str();
    alert.setSubVer.insert(strSetSubVer);
    alert.nPriority = params[5].get_int();
    alert.nID = params[6].get_int();
    if (params.size() > 7)
        alert.nCancel = params[7].get_int();
    alert.nVersion = PROTOCOL_VERSION;
    alert.nRelayUntil = GetAdjustedTime() + 24*60*60;
    alert.nExpiration = GetAdjustedTime() + 24*60*60;

    CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
    sMsg << (CUnsignedAlert)alert;
    alert.vchMsg = vector<unsigned char>(sMsg.begin(), sMsg.end());

    vector<unsigned char> vchPrivKey = ParseHex(params[1].get_str());
    key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
    if (!key.Sign(Hash(alert.vchMsg.begin(), alert.vchMsg.end()), alert.vchSig))
        throw runtime_error(
            "Unable to sign alert, check private key?\n");  
    if(!alert.ProcessAlert()) 
        throw runtime_error(
            "Failed to process alert.\n");

    CHomeNode::getHomeNode()->relayAlert(alert);

    Object result;
    result.push_back(Pair("strStatusBar", alert.strStatusBar));
    result.push_back(Pair("nVersion", alert.nVersion));
    result.push_back(Pair("nMinVer", alert.nMinVer));
    result.push_back(Pair("nMaxVer", alert.nMaxVer));
    result.push_back(Pair("setSubVer", strSetSubVer));
    result.push_back(Pair("nPriority", alert.nPriority));
    result.push_back(Pair("nID", alert.nID));
    if (alert.nCancel > 0)
        result.push_back(Pair("nCancel", alert.nCancel));
    return result;
}

Value showalerts(const Array& params, bool fHelp)
{
    if (fHelp)
        throw runtime_error(
            "showalerts\n");

    Object result;

    LOCK(cs_mapAlerts);
    // Display alerts table
    for (map<uint256, CAlert>::iterator mi = mapAlerts.begin(); mi != mapAlerts.end();)
    {
        const CAlert& alert = (*mi).second;
        result.push_back(Pair("strStatusBar", alert.strStatusBar));
        result.push_back(Pair("nVersion", alert.nVersion));
        result.push_back(Pair("nMinVer", alert.nMinVer));
        result.push_back(Pair("nMaxVer", alert.nMaxVer));
        std::string strSetSubVer;
        for(std::string str : alert.setSubVer) strSetSubVer += str;
        result.push_back(Pair("setSubVer", strSetSubVer));
        result.push_back(Pair("nPriority", alert.nPriority));
        result.push_back(Pair("nID", alert.nID));
        if (alert.nCancel > 0)
            result.push_back(Pair("nCancel", alert.nCancel));
        result.push_back(Pair("active", alert.IsInEffect()));
        mi++;
    }
    return result;
}
