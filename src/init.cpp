// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "txdb.h"
#include "walletdb.h"
#include "bitcoinrpc.h"
#include "net.h"
#include "init.h"
#include "util.h"
#include "miner.h"
#include "ui_interface.h"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/filesystem/convenience.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <openssl/crypto.h>
#ifdef QT_GUI
#include <QApplication>
#include <QProcess>
#endif

#ifndef WIN32
#include <signal.h>
#endif


using namespace std;
using namespace boost;

CWallet*               g_tughlaqWallet;
CClientUIInterface     uiInterface;
std::string            g_strWalletFileName;
unsigned int           g_nNodeLifespan;
//unsigned int           nDerivationMethodIndex;
//unsigned int           nMinerSleep;

bool                   fUseFastIndex;
bool                   fConfChange;
bool                   fEnforceCanonical;

extern bool fDiscover ;
extern bool fUseUPnP ;

#if defined(USE_SSE2)
#if !defined(MAC_OSX) && (defined(_M_IX86) || defined(__i386__) || defined(__i386))
#ifdef _MSC_VER
// MSVC 64bit is unable to use inline asm
#include <intrin.h>
#else
// GCC Linux or i686-w64-mingw32
#include <cpuid.h>
#endif
#endif
#endif

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

void ExitTimeout(void* parg)
{
#ifdef WIN32
    MilliSleep(5000);
    ExitProcess(0);
#endif
}

void StartShutdown()
{
#ifdef QT_GUI
    // ensure we leave the Qt main loop for a clean GUI exit (Shutdown() is called in bitcoin.cpp afterwards)
    uiInterface.QueueShutdown();
#else
    // Without UI, Shutdown() can simply be started in a new thread
    NewThread(Shutdown, NULL);
#endif
}

void Shutdown(void* parg)
{
    static CCriticalSection cs_Shutdown;
    static bool fTaken;

    // Make this thread recognisable as the shutdown thread
    RenameThread("tughlaq-shutoff");

    ShutdownRPCMining();
    GenerateTughlaq(false, NULL);
    bool fFirstThread = false;
    {
        TRY_LOCK(cs_Shutdown, lockShutdown);
        if (lockShutdown)
        {
            fFirstThread = !fTaken;
            fTaken = true;
        }
    }
    static bool fExit;
    if (fFirstThread)
    {
        fShutdown = true;
        g_nTransactionsUpdated++;
//        CTxDB().Close();
        bitdb.Flush(false);
	CHomeNode::getHomeNode()->StopNode();
	delete CHomeNode::getHomeNode();
        bitdb.Flush(true);

#ifdef QT_GUI
	std::cout << "frestart flag is set to " << fRestart << std::endl;
        if (fRestart)
        {
            if (fBootstrapTurbo && boost::filesystem::exists(GetDataDir() / "bootstrap" / "blk0001.dat"))
            {
                try
                {
                    // Leveldb instance destruction
                    CTxDB().Destroy();
                    boost::filesystem::rename(GetDataDir() / "bootstrap" / "blk0001.dat", GetDataDir() / "blk0001.dat");
                    boost::filesystem::rename(GetDataDir() / "bootstrap" / "txleveldb", GetDataDir() / "txleveldb");
                    if (fBootstrapConfig)
                        boost::filesystem::rename(GetDataDir() / "bootstrap" / "tughlaq.conf", GetDataDir() / "tughlaq.conf");
                    boost::filesystem::remove_all(GetDataDir() / "bootstrap");

                    RestartWallet(NULL, true);
                }
                catch (std::exception &e)
	       	{
                    printf("Bootstrapturbo filesystem error!\n");
                }
            }
            else if (fRescan)
            {
                RestartWallet("-rescan", true);
            }
            else
            {
                RestartWallet(NULL, true);
            }
        }
#else
        if (fBootstrapTurbo && boost::filesystem::exists(GetDataDir() / "bootstrap" / "blk0001.dat"))
        {
            try
            {
                // Leveldb instance destruction
                CTxDB().Destroy();
                boost::filesystem::rename(GetDataDir() / "bootstrap" / "blk0001.dat", GetDataDir() / "blk0001.dat");
                boost::filesystem::rename(GetDataDir() / "bootstrap" / "txleveldb", GetDataDir() / "txleveldb");
                if (fBootstrapConfig)
                    boost::filesystem::rename(GetDataDir() / "bootstrap" / "tughlaq.conf", GetConfigFile());
                boost::filesystem::remove_all(GetDataDir() / "bootstrap");

                boost::filesystem::path pathBootstrapTurbo(GetDataDir() / "bootstrap_MBT.zip");
                boost::filesystem::path pathBootstrap(GetDataDir() / "bootstrap.dat");
                if (boost::filesystem::exists(pathBootstrapTurbo))
                {
                    boost::filesystem::remove(pathBootstrapTurbo);
                }
                if (boost::filesystem::exists(pathBootstrap))
                {
                    boost::filesystem::remove(pathBootstrap);
                }
            }
            catch (std::exception &e)
	    {
                printf("Bootstrapturbo filesystem error!\n");
            }
        }
#endif
        boost::filesystem::remove(GetPidFile());
	Tughlaq::UnregisterWallet(g_tughlaqWallet);
        delete g_tughlaqWallet;

        NewThread(ExitTimeout, NULL);
        MilliSleep(50);
        printf("Tughlaq exited\n\n");
        fExit = true;

#ifndef QT_GUI
        // ensure non-UI client gets exited here, but let Bitcoin-Qt reach 'return 0;' in bitcoin.cpp
        exit(0);
#endif
    }
    else
    {
        while (!fExit)
            MilliSleep(500);
        MilliSleep(100);
        ExitThread(0);
    }
}

#ifdef QT_GUI
// Restart wallet
void RestartWallet(const char *parm, bool fOldParms)
{
    QStringList newArgv(QApplication::instance()->arguments());
    QString command;

    if (fNewVersion && !fBootstrapTurbo && !fRescan && !fEncrypt) // fNewVersion could be true while trying to do other restarts
    {
        // Remove old bootstraps
        boost::filesystem::path pathBootstrapTurbo(GetDataDir() / "bootstrap_VRM.zip");
        boost::filesystem::path pathBootstrap(GetDataDir() / "bootstrap.dat");
        if (boost::filesystem::exists(pathBootstrapTurbo))
        {
            boost::filesystem::remove(pathBootstrapTurbo);
        }
        if (boost::filesystem::exists(pathBootstrap))
        {
            boost::filesystem::remove(pathBootstrap);
        }

#ifdef WIN32
        // If Windows, replace argv[0] with the exe installer and restart.
        parm = NULL;
        fOldParms = false;
        newArgv.clear();
        // Installer created by Inno Setup
        command = QString(GetDataDir().string().c_str()) + QString("/") + QString(GetArg("-vFileName","tughlaq-setup.exe").c_str());
#else
#ifdef MAC_OSX
        // If Mac, replace argv[0] with Finder and pass the location of the pkg file.
        parm = NULL;
        fOldParms = false;
        newArgv.clear();
        // Installer created by pkgbuild or Package Maker
        command = QString("/usr/bin/open");
        newArgv.append(QString(GetDataDir().c_str()) + QString("/") + QString(GetArg("-vFileName","tughlaq-setup.pkg").c_str()));
#else
        // If Linux, just restart (already extracted tughlaq-qt from the zip in downloader.cpp).
        parm = NULL;
        fOldParms = false;
        newArgv.clear();
        // Installer created by makeself.sh
        command = QString(GetDataDir().c_str()) + QString("/") + QString(GetArg("-vFileName","tughlaq-setup.run").c_str());
        newArgv.append(QString("--target"));
        newArgv.append(QString(GetProgramDir().c_str()));
        newArgv.append(QString("--nox11"));
        // Make executable
        boost::filesystem::path installer(GetDataDir() / GetArg("-vFileName","tughlaq-setup.run"));
        boost::filesystem::permissions(installer, status(installer).permissions() | boost::filesystem::owner_exe | boost::filesystem::group_exe);
#endif
#endif
    }
    else
    {
        command = newArgv[0];
        if (!fOldParms)
        {
            newArgv.clear();
        }
        else
        {
            newArgv.removeFirst();
        }
        newArgv.append(QString("-restart"));
    }

    if ((fOldParms && g_mapArgs.count("-rescan")))
        newArgv.removeOne(QString("-rescan"));

    if (parm)
    {
        newArgv.append(QString(parm));
    }

    // Spawn a new instance.
    QProcess::startDetached(command, newArgv);

    return;
}
#endif

void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}

void HandleSIGHUP(int)
{
    fReopenDebugLog = true;
}





//////////////////////////////////////////////////////////////////////////////
//
// Start
//
#if !defined(QT_GUI)

extern void noui_connect();
int main(int argc, char* argv[])
{
    bool fRet = false;

    // Connect bitcoind signal handlers
    noui_connect();

    try
    {
        //
        // Parameters
        //
        // If Qt is used, parameters/bitcoin.conf are parsed in qt/bitcoin.cpp's main()
        ParseParameters(argc, argv);
        // Restarting
        if (g_mapArgs.count("-restart"))
       	{
            // a wallet restart was issued
            SoftSetBoolArg("-restart", true);
        }
        if (!boost::filesystem::is_directory(GetDataDir(false)))
        {
            fprintf(stderr, "Error: Specified directory does not exist\n");
            Shutdown(NULL);
        }
        ReadConfigFile(g_mapArgs, g_mapMultiArgs);

        if (g_mapArgs.count("-?") || g_mapArgs.count("--help"))
        {
            // First part of help message is specific to bitcoind / RPC client
            std::string strUsage = _("Tughlaq Version") + " " + FormatFullVersion() + "\n\n" +
                _("Usage:") + "\n" +
                  "  tughlaqd [options]                     " + "\n" +
                  "  tughlaqd [options] <command> [params]  " + _("Send command to -server or tughlaqd") + "\n" +
                  "  tughlaqd [options] help                " + _("List commands") + "\n" +
                  "  tughlaqd [options] help <command>      " + _("Get help for a command") + "\n";

            strUsage += "\n" + HelpMessage();

            fprintf(stdout, "%s", strUsage.c_str());
            Shutdown(NULL);
        }

        // Command-line RPC
        for (int i = 1; i < argc; i++)
            if (!IsSwitchChar(argv[i][0]) && !boost::algorithm::istarts_with(argv[i], "tughlaq:"))
                fCommandLine = true;

        if (fCommandLine)
        {
            int ret = CommandLineRPC(argc, argv);
            exit(ret);
        }

        //AppInit is common between CLI main and GUI main
        if (AppInit() )
	{
        // Loop until process is exit()ed from shutdown() function,
        // called from ThreadRPCServer thread when a "stop" command is received.
	// Corresponding loop is app.exec in QT app
	    while (1)
            {
                printf ("\n[sleep]");
                MilliSleep(5000);
            }
	}
    }
    catch (std::exception& e)
    {
        PrintException(&e, "AppInit()");
    }
    catch (...)
    {
        PrintException(NULL, "AppInit()");
    }

    if (!fRet) Shutdown(NULL);

    if (fRet && fDaemon)
        return 0;

    return 1;
}
#endif

bool static InitError(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, _("Tughlaq"), CClientUIInterface::OK | CClientUIInterface::MODAL);
    return false;
}

bool static InitWarning(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, _("Tughlaq"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
    return true;
}


bool static Bind(const CService &addr, bool fError)
{
    printf("\nInside static Bind with addr [%s]\n", addr.ToString().c_str());
    CHomeNode *homeNode = CHomeNode::getHomeNode();
    if (homeNode->IsLimited(addr))
    {
    printf("\nLimited address [%s] returning false %s:%d\n", addr.ToString().c_str(), __FILE__, __LINE__);
        return false;
    }

    std::string strError;
    if (!homeNode->BindListenPort(addr, strError))
    {
        if (fError) return InitError(strError);
        return false;
    }
    return true;
}

// Core-specific options shared between UI and daemon
std::string HelpMessage()
{
    string strUsage = _("Options:") + "\n" +
        "  -?                     " + _("This help message") + "\n" +
        "  -conf=<file>           " + _("Specify configuration file path (default: <cwd>/tughlaq.conf)") + "\n" +
        "  -pid=<file>            " + _("Specify pid file (default: tughlaqd.pid)") + "\n" +
        "  -datadir=<dir>         " + _("Specify data directory") + "\n" +
        "  -wallet=<dir>          " + _("Specify wallet file (within data directory)") + "\n" +
        "  -dbcache=<n>           " + _("Set database cache size in megabytes (default: 25)") + "\n" +
        "  -dblogsize=<n>         " + _("Set database disk log size in megabytes (default: 100)") + "\n" +
        "  -timeout=<n>           " + _("Specify connection timeout in milliseconds (default: 5000)") + "\n" +
        "  -proxy=<ip:port>       " + _("Connect through socks proxy") + "\n" +
        "  -socks=<n>             " + _("Select the version of socks proxy to use (4-5, default: 5)") + "\n" +
        "  -tor=<ip:port>         " + _("Use proxy to reach tor hidden services (default: same as -proxy)") + "\n"
        "  -dns                   " + _("Allow DNS lookups for -addnode, -seednode and -connect") + "\n" +
        "  -port=<port>           " + _("Listen for connections on <port> (default: 41976 or testnet: 41973)") + "\n" +
        "  -maxconnections=<n>    " + _("Maintain at most <n> connections to peers (default: 125)") + "\n" +
        "  -addnode=<ip>          " + _("Add a node to connect to and attempt to keep the connection open") + "\n" +
        "  -connect=<ip>          " + _("Connect only to the specified node(s)") + "\n" +
        "  -seednode=<ip>         " + _("Connect to a node to retrieve peer addresses, and disconnect") + "\n" +
        "  -externalip=<ip>       " + _("Specify your own public address") + "\n" +
        "  -onlynet=<net>         " + _("Only connect to nodes in network <net> (IPv4, IPv6 or Tor)") + "\n" +
        "  -discover              " + _("Discover own IP address (default: 1 when listening and no -externalip)") + "\n" +
        "  -irc                   " + _("Find peers using internet relay chat (default: 0)") + "\n" +
        "  -listen                " + _("Accept connections from outside (default: 1 if no -proxy or -connect)") + "\n" +
        "  -bind=<addr>           " + _("Bind to given address. Use [host]:port notation for IPv6") + "\n" +
        "  -dnsseed               " + _("Find peers using DNS lookup (default: 1)") + "\n" +
        "  -banscore=<n>          " + _("Threshold for disconnecting misbehaving peers (default: 100)") + "\n" +
        "  -bantime=<n>           " + _("Number of seconds to keep misbehaving peers from reconnecting (default: 86400)") + "\n" +
        "  -maxreceivebuffer=<n>  " + _("Maximum per-connection receive buffer, <n>*1000 bytes (default: 5000)") + "\n" +
        "  -maxsendbuffer=<n>     " + _("Maximum per-connection send buffer, <n>*1000 bytes (default: 1000)") + "\n" +

#ifdef USE_UPNP
#if USE_UPNP
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 1 when listening)") + "\n" +
#else
        "  -upnp                  " + _("Use UPnP to map the listening port (default: 0)") + "\n" +
#endif
#endif
        "  -detachdb              " + _("Detach block and address databases. Increases shutdown time (default: 0)") + "\n" +
        "  -paytxfee=<amt>        " + _("Fee per KB to add to transactions you send") + "\n" +
        "  -mininput=<amt>        " + _("When creating transactions, ignore inputs with value less than this (default: 0.01)") + "\n" +
#ifdef QT_GUI
        "  -server                " + _("Accept command line and JSON-RPC commands") + "\n" +
#endif
#if !defined(WIN32) && !defined(QT_GUI)
        "  -daemon                " + _("Run in the background as a daemon and accept commands") + "\n" +
#endif
        "  -testnet               " + _("Use the test network") + "\n" +
        "  -debug                 " + _("Output extra debugging information. Implies all other -debug* options") + "\n" +
        "  -debugnet              " + _("Output extra network debugging information") + "\n" +
        "  -logtimestamps         " + _("Prepend debug output with timestamp") + "\n" +
        "  -shrinkdebugfile       " + _("Shrink debug.log file on client startup (default: 1 when no -debug)") + "\n" +
        "  -printtoconsole        " + _("Send trace/debug info to console instead of debug.log file") + "\n" +
#ifdef WIN32
        "  -printtodebugger       " + _("Send trace/debug info to debugger") + "\n" +
#endif
        "  -rpcuser=<user>        " + _("Username for JSON-RPC connections") + "\n" +
        "  -rpcpassword=<pw>      " + _("Password for JSON-RPC connections") + "\n" +
        "  -rpcport=<port>        " + _("Listen for JSON-RPC connections on <port> (default: 33987 or testnet: 32987)") + "\n" +
        "  -rpcallowip=<ip>       " + _("Allow JSON-RPC connections from specified IP address") + "\n" +
        "  -rpcconnect=<ip>       " + _("Send commands to node running on <ip> (default: 127.0.0.1)") + "\n" +
        "  -blocknotify=<cmd>     " + _("Execute command when the best block changes (%s in cmd is replaced by block hash)") + "\n" +
        "  -walletnotify=<cmd>    " + _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)") + "\n" +
        "  -confchange            " + _("Require a confirmations for change (default: 0)") + "\n" +
        "  -enforcecanonical      " + _("Enforce transaction scripts to use canonical PUSH operators (default: 1)") + "\n" +
        "  -upgradewallet         " + _("Upgrade wallet to latest format") + "\n" +
        "  -keypool=<n>           " + _("Set key pool size to <n> (default: 100)") + "\n" +
        "  -rescan                " + _("Rescan the block chain for missing wallet transactions") + "\n" +
        "  -salvagewallet         " + _("Attempt to recover private keys from a corrupt wallet.dat") + "\n" +
        "  -checkblocks=<n>       " + _("How many blocks to check at startup (default: 20, 0 = all)") + "\n" +
        "  -checklevel=<n>        " + _("How thorough the block verification is (0-6, default: 1)") + "\n" +
        "  -loadblock=<file>      " + _("Imports blocks from external blk000?.dat file") + "\n" +

        "\n" + _("Block creation options:") + "\n" +
        "  -blockminsize=<n>      "   + _("Set minimum block size in bytes (default: 0)") + "\n" +
        "  -blockmaxsize=<n>      "   + _("Set maximum block size in bytes (default: 250000)") + "\n" +
        "  -blockprioritysize=<n> "   + _("Set maximum size of high-priority/low-fee transactions in bytes (default: 27000)") + "\n" +

        "\n" + _("SSL options: (see the Bitcoin Wiki for SSL setup instructions)") + "\n" +
        "  -rpcssl                                  " + _("Use OpenSSL (https) for JSON-RPC connections") + "\n" +
        "  -rpcsslcertificatechainfile=<file.cert>  " + _("Server certificate file (default: server.cert)") + "\n" +
        "  -rpcsslprivatekeyfile=<file.pem>         " + _("Server private key (default: server.pem)") + "\n" +
        "  -rpcsslciphers=<ciphers>                 " + _("Acceptable ciphers (default: TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH)") + "\n";

    return strUsage;
}

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 *  This function is common between CLI main and QT main (qt/bitcoin.cpp)
 */
bool AppInit()
{
    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable Data Execution Prevention (DEP)
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
// We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
// which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL) setProcDEPPol(PROCESS_DEP_ENABLE);
#endif
#ifndef WIN32
    umask(077);

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);
#endif

#if defined(USE_SSE2)
    unsigned int cpuid_edx=0;
#if !defined(MAC_OSX) && (defined(_M_IX86) || defined(__i386__) || defined(__i386))
    // 32bit x86 Linux or Windows, detect cpuid features
#if defined(_MSC_VER)
    // MSVC
    int x86cpuid[4];
    __cpuid(x86cpuid, 1);
    cpuid_edx = (unsigned int)buffer[3];
#else
    // Linux or i686-w64-mingw32 (gcc-4.6.3)
    unsigned int eax, ebx, ecx;
    __get_cpuid(1, &eax, &ebx, &ecx, &cpuid_edx);
#endif
#endif
#endif

    // ********************************************************* Step 2: parameter interactions

    g_nNodeLifespan = GetArg("-addrlifespan", 7);
    fUseFastIndex = GetBoolArg("-fastindex", true);
//    nMinerSleep = GetArg("-minersleep", 500);

//    nDerivationMethodIndex = 0;

    fTestNet = GetBoolArg("-testnet");
    if (fTestNet)
    {
        SoftSetBoolArg("-irc", false);
    }

    // Restarting
    if (g_mapArgs.count("-restart"))
    {
        SoftSetBoolArg("-restart", true);
    }

    if (g_mapArgs.count("-bind"))
    {
        // when specifying an explicit binding address, you want to listen on it
        // even when -connect or -proxy is specified
        SoftSetBoolArg("-listen", true);
    }

    if (g_mapArgs.count("-connect") && g_mapMultiArgs["-connect"].size() > 0)
    {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        SoftSetBoolArg("-dnsseed", false);
        SoftSetBoolArg("-listen", false);
    }

    if (g_mapArgs.count("-proxy"))
    {
        // to protect privacy, do not listen by default if a proxy server is specified
        SoftSetBoolArg("-listen", false);
    }

    if (!GetBoolArg("-listen", true))
    {
        // do not map ports or try to retrieve public IP when not listening (pointless)
        SoftSetBoolArg("-upnp", false);
        SoftSetBoolArg("-discover", false);
    }

    if (g_mapArgs.count("-externalip"))
    {
        // if an explicit public IP is specified, do not try to find others
        SoftSetBoolArg("-discover", false);
    }

    if (GetBoolArg("-salvagewallet"))
    {
        // Rewrite just private keys: rescan to find transactions
        SoftSetBoolArg("-rescan", true);
    }

    // ********************************************************* Step 3: parameter-to-internal-flags

    fDebug = GetBoolArg("-debug");

    // -debug implies fDebug*
    if (fDebug)
        fDebugNet = true;
    else
        fDebugNet = GetBoolArg("-debugnet");

    bitdb.SetDetach(GetBoolArg("-detachdb", false));

#if !defined(WIN32) && !defined(QT_GUI)
    fDaemon = GetBoolArg("-daemon");
#else
    fDaemon = false;
#endif

    if (fDaemon)
        fServer = true;
    else
        fServer = GetBoolArg("-server");

    /* force fServer when running without GUI */
#if !defined(QT_GUI)
    fServer = true;
#endif
    fPrintToConsole = GetBoolArg("-printtoconsole");
    fPrintToDebugger = GetBoolArg("-printtodebugger");
    fLogTimestamps = GetBoolArg("-logtimestamps");

    if (g_mapArgs.count("-timeout"))
    {
        int nNewTimeout = GetArg("-timeout", 5000);
        if (nNewTimeout > 0 && nNewTimeout < 600000)
            nConnectTimeout = nNewTimeout;
    }

    if (g_mapArgs.count("-paytxfee"))
    {
        if (!ParseMoney(g_mapArgs["-paytxfee"], nTransactionFee))
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s'"), g_mapArgs["-paytxfee"].c_str()));
        if (nTransactionFee > 0.25 * COIN)
            InitWarning(_("Warning: -paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
    }

    fConfChange = GetBoolArg("-confchange", false);
    fEnforceCanonical = GetBoolArg("-enforcecanonical", true);

    if (g_mapArgs.count("-mininput"))
    {
        if (!ParseMoney(g_mapArgs["-mininput"], nMinimumInputValue))
            return InitError(strprintf(_("Invalid amount for -mininput=<amount>: '%s'"), g_mapArgs["-mininput"].c_str()));
    }

    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log

    std::string strDataDir = GetDataDir().string();
    g_strWalletFileName = GetArg("-wallet", "wallet.dat");

    // strWalletFileName must be a plain filename without a directory
    if (g_strWalletFileName != boost::filesystem::basename(g_strWalletFileName) + boost::filesystem::extension(g_strWalletFileName))
        return InitError(strprintf(_("Wallet %s resides outside data directory %s."), g_strWalletFileName.c_str(), strDataDir.c_str()));

    // Make sure only a single Tughlaq process is using the data directory.
    boost::filesystem::path pathLockFile = GetDataDir() / ".lock";
    FILE* file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file);
    static boost::interprocess::file_lock lock(pathLockFile.string().c_str());

    if (!lock.try_lock())
        return InitError(strprintf(_("Cannot obtain a lock on data directory %s.  Tughlaq is probably already running."), strDataDir.c_str()));

#if !defined(WIN32) && !defined(QT_GUI)
    if (fDaemon)
    {
        // Daemonize
        pid_t pid = fork();
        if (pid < 0)
        {
            fprintf(stderr, "Error: fork() returned %d errno %d\n", pid, errno);
            return false;
        }
        if (pid > 0)
        {
            CreatePidFile(GetPidFile(), pid);
            return true;
        }

        pid_t sid = setsid();
        if (sid < 0)
            fprintf(stderr, "Error: setsid() returned %d errno %d\n", sid, errno);
    }
#endif

    if (GetBoolArg("-shrinkdebugfile", !fDebug))
        ShrinkDebugFile();

    printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    printf("Tughlaq Version %s (%s)\n", FormatFullVersion().c_str(), CLIENT_DATE.c_str());
    printf("Using OpenSSL version %s\n", SSLeay_version(SSLEAY_VERSION));
    
    if (!fLogTimestamps)
        printf("Startup time: %s\n", DateTimeStrFormat("%x %H:%M:%S", GetTime()).c_str());
    
    printf("Default data directory %s\n", GetDefaultDataDir().string().c_str());
    printf("Used data directory %s\n", strDataDir.c_str());
    std::ostringstream strErrors;

    if (fDaemon)
        fprintf(stdout, "Tughlaq server starting\n");

    int64_t nStart;

#if defined(USE_SSE2)
    scrypt_detect_sse2(cpuid_edx);
#endif

    // ********************************************************* Step 5: verify database integrity

    uiInterface.InitMessage(_("Verifying database integrity..."));

    if (!bitdb.Open(GetDataDir()))
    {
        string msg = strprintf(_("Error initializing database environment %s!"
                                 " To recover, BACKUP THAT DIRECTORY, then remove"
                                 " everything from it except for wallet.dat."), strDataDir.c_str());
        return InitError(msg);
    }

    if (GetBoolArg("-salvagewallet"))
    {
        // Recover readable keypairs:
        if (!CWalletDB::Recover(bitdb, g_strWalletFileName, true))
            return false;
    }

    if (filesystem::exists(GetDataDir() / g_strWalletFileName))
    {
        CDBEnv::VerifyResult r = bitdb.Verify(g_strWalletFileName, CWalletDB::Recover);
        if (r == CDBEnv::RECOVER_OK)
        {
            string msg = strprintf(_("Warning: wallet.dat corrupt, data salvaged!"
                                     " Original wallet.dat saved as wallet.{timestamp}.bak in %s; if"
                                     " your balance or transactions are incorrect you should"
                                     " restore from a backup."), strDataDir.c_str());
            uiInterface.ThreadSafeMessageBox(msg, _("Tughlaq"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        }
        if (r == CDBEnv::RECOVER_FAIL)
            return InitError(_("wallet.dat corrupt, salvage failed"));
    }

    // ********************************************************* Step 6: network initialization

    CHomeNode *homeNode = CHomeNode::getHomeNode();

    int nSocksVersion = GetArg("-socks", 5);

    if (nSocksVersion != 4 && nSocksVersion != 5)
        return InitError(strprintf(_("Unknown -socks proxy version requested: %i"), nSocksVersion));

    if (g_mapArgs.count("-onlynet"))
    {
        std::set<enum Network> nets;
        BOOST_FOREACH(std::string snet, g_mapMultiArgs["-onlynet"])
       	{
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet.c_str()));
            nets.insert(net);
        }
        for (int n = 0; n < NET_MAX; n++)
       	{
            enum Network net = (enum Network)n;
            if (!nets.count(net))
                homeNode->SetLimited(net, true);
        }
    }
#if defined(USE_IPV6)
#if ! USE_IPV6
    else
        homeNode->SetLimited(NET_IPV6, true);
#endif
#endif

    CService addrProxy;
    bool fProxy = false;
    if (g_mapArgs.count("-proxy"))
    {
        addrProxy = CService(g_mapArgs["-proxy"], 9050);
        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address: '%s'"), g_mapArgs["-proxy"].c_str()));

        if (!homeNode->IsLimited(NET_IPV4))
            SetProxy(NET_IPV4, addrProxy, nSocksVersion);
        if (nSocksVersion > 4)
       	{
#ifdef USE_IPV6
            if (!homeNode->IsLimited(NET_IPV6))
                SetProxy(NET_IPV6, addrProxy, nSocksVersion);
#endif
            SetNameProxy(addrProxy, nSocksVersion);
        }
        fProxy = true;
    }

    // -tor can override normal proxy, -notor disables tor entirely
    if (!(g_mapArgs.count("-tor") && g_mapArgs["-tor"] == "0") && (fProxy || g_mapArgs.count("-tor")))
    {
        CService addrOnion;
        if (!g_mapArgs.count("-tor"))
            addrOnion = addrProxy;
        else
            addrOnion = CService(g_mapArgs["-tor"], 9050);
        if (!addrOnion.IsValid())
            return InitError(strprintf(_("Invalid -tor address: '%s'"), g_mapArgs["-tor"].c_str()));

        SetProxy(NET_TOR, addrOnion, 5);
        homeNode->SetReachable(NET_TOR, true);
    }

    // see Step 2: parameter interactions for more information about these
    fNoListen = !GetBoolArg("-listen", true);
    fDiscover = GetBoolArg("-discover", true);
    fNameLookup = GetBoolArg("-dns", true);
#ifdef USE_UPNP
    fUseUPnP = GetBoolArg("-upnp", USE_UPNP);
#endif

    bool fBound = false;
    if (!fNoListen)
    {
        std::string strError;
        if (g_mapArgs.count("-bind") && g_mapMultiArgs["-bind"].size() > 1)
       	{
            for(std::string strBind : g_mapMultiArgs["-bind"])
	    {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, homeNode->GetListenPort(), false))
                    return InitError(strprintf(_("Cannot resolve -bind address: '%s'"), strBind.c_str()));
                fBound |= Bind(addrBind, true);
            }
        }
       	else
       	{
            struct in_addr inaddr_any;
            inaddr_any.s_addr = INADDR_ANY;
#ifdef USE_IPV6
            if (!homeNode->IsLimited(NET_IPV6))
                fBound |= Bind(CService(in6addr_any, homeNode->GetListenPort()), false);
#endif
            if (!homeNode->IsLimited(NET_IPV4))
                fBound |= Bind(CService(inaddr_any, homeNode->GetListenPort()), !fBound);
        }
        if (!fBound)
            return InitError(_("Failed to listen on any port. Use -listen=0 if you want this."));
    }

    if (g_mapArgs.count("-externalip"))
    {
        for(string strAddr : g_mapMultiArgs["-externalip"])
       	{
            CService addrLocal(strAddr, homeNode->GetListenPort(), fNameLookup);
            if (!addrLocal.IsValid())
                return InitError(strprintf(_("Cannot resolve -externalip address: '%s'"), strAddr.c_str()));
            homeNode->AddLocal(CService(strAddr, homeNode->GetListenPort(), fNameLookup), CHomeNode::LOCAL_MANUAL);
        }
    }

    if (g_mapArgs.count("-reservebalance")) // ppcoin: reserve balance amount
    {
        if (!ParseMoney(g_mapArgs["-reservebalance"], nReserveBalance))
        {
            InitError(_("Invalid amount for -reservebalance=<amount>"));
            return false;
        }
    }

    for(string strDest: g_mapMultiArgs["-seednode"])
        homeNode->AddOneShot(strDest);

    // ********************************************************* Step 7: load blockchain

    if (!bitdb.Open(GetDataDir()))
    {
        string msg = strprintf(_("Error initializing database environment %s!"
                                 " To recover, BACKUP THAT DIRECTORY, then remove"
                                 " everything from it except for wallet.dat."), strDataDir.c_str());
        return InitError(msg);
    }

    if (GetBoolArg("-loadblockindextest"))
    {
        CTxDB txdb("r");
        txdb.LoadBlockIndex();
        Tughlaq::PrintBlockTree();
        return false;
    }

    uiInterface.InitMessage(_("Loading block index..."));
    printf("Loading block index...\n");
    nStart = GetTimeMillis();
    if (!Tughlaq::LoadBlockIndex(true))
        return InitError(_("Error loading blkindex.dat"));


    // as LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill tughlaq-qt during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (fRequestShutdown)
    {
        printf("Shutdown requested. Exiting.\n");
        return false;
    }
    printf(" block index %15" PRId64 "ms\n", GetTimeMillis() - nStart);

    if (GetBoolArg("-printblockindex") || GetBoolArg("-printblocktree"))
    {
        Tughlaq::PrintBlockTree();
        return false;
    }

    if (g_mapArgs.count("-printblock"))
    {
        string strMatch = g_mapArgs["-printblock"];
        int nFound = 0;
        for (map<uint256, CBlockIndex*>::iterator mi = g_mapBlockIndex.begin(); mi != g_mapBlockIndex.end(); ++mi)
        {
            uint256 hash = (*mi).first;
            if (strncmp(hash.ToString().c_str(), strMatch.c_str(), strMatch.size()) == 0)
            {
                CBlockIndex* pindex = (*mi).second;
                CBlock block;
                block.ReadFromDisk(pindex);
                block.BuildMerkleTree();
                block.print();
                printf("\n");
                nFound++;
            }
        }
        if (nFound == 0)
            printf("No blocks matching %s were found\n", strMatch.c_str());
        return false;
    }

    // ********************************************************* Step 8: load wallet

    uiInterface.InitMessage(_("Loading wallet..."));
    printf("Loading wallet...\n");
    nStart = GetTimeMillis();
    fFirstRun = true;
    g_tughlaqWallet = new CWallet(g_strWalletFileName);
    DBErrors nLoadWalletRet = g_tughlaqWallet->LoadWallet(fFirstRun);
    if (nLoadWalletRet != DB_LOAD_OK)
    {
        if (nLoadWalletRet == DB_CORRUPT)
            strErrors << _("Error loading wallet.dat: Wallet corrupted") << "\n";
        else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
        {
            string msg(_("Warning: error reading wallet.dat! All keys read correctly, but transaction data"
                         " or address book entries might be missing or incorrect."));
            uiInterface.ThreadSafeMessageBox(msg, _("Tughlaq"), CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        }
        else if (nLoadWalletRet == DB_TOO_NEW)
            strErrors << _("Error loading wallet.dat: Wallet requires newer version of Tughlaq") << "\n";
        else if (nLoadWalletRet == DB_NEED_REWRITE)
        {
            strErrors << _("Wallet needed to be rewritten: restart Tughlaq to complete") << "\n";
            printf("%s", strErrors.str().c_str());
            return InitError(strErrors.str());
        }
        else
            strErrors << _("Error loading wallet.dat") << "\n";
    }

    if (GetBoolArg("-upgradewallet", fFirstRun))
    {
        int nMaxVersion = GetArg("-upgradewallet", 0);
        if (nMaxVersion == 0) // the -upgradewallet without argument case
        {
            printf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
            nMaxVersion = CLIENT_VERSION;
            g_tughlaqWallet->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
        }
        else
            printf("Allowing wallet upgrade up to %i\n", nMaxVersion);
        if (nMaxVersion < g_tughlaqWallet->GetVersion())
            strErrors << _("Cannot downgrade wallet") << "\n";
        g_tughlaqWallet->SetMaxVersion(nMaxVersion);
    }

    if (fFirstRun)
    {
        // Create new keyUser and set as default key
        RandAddSeedPerfmon();

        CPubKey newDefaultKey;
        if (g_tughlaqWallet->GetKeyFromPool(newDefaultKey, false))
       	{
            g_tughlaqWallet->SetDefaultKey(newDefaultKey);
            if (!g_tughlaqWallet->SetAddressBookName(g_tughlaqWallet->vchDefaultKey.GetID(), ""))
                strErrors << _("Cannot write default address") << "\n";
        }
    }

    printf("%s", strErrors.str().c_str());
    printf(" wallet      %15" PRId64 "ms\n", GetTimeMillis() - nStart);

    Tughlaq::RegisterWallet(g_tughlaqWallet);

    CBlockIndex *pindexRescan = g_pindexBest;
    if (GetBoolArg("-rescan"))
        pindexRescan = g_pindexGenesisBlock;
    else
    {
        CWalletDB walletdb(g_strWalletFileName);
        CBlockLocator locator;
        if (walletdb.ReadBestBlock(locator))
            pindexRescan = locator.GetBlockIndex();
    }
    if (g_pindexBest != pindexRescan && g_pindexBest && pindexRescan && g_pindexBest->nHeight > pindexRescan->nHeight)
    {
        uiInterface.InitMessage(_("Rescanning..."));
        printf("Rescanning last %i blocks (from block %i)...\n", g_pindexBest->nHeight - pindexRescan->nHeight, pindexRescan->nHeight);
        nStart = GetTimeMillis();
        g_tughlaqWallet->ScanForWalletTransactions(pindexRescan, true);
        printf(" rescan      %15" PRId64 "ms\n", GetTimeMillis() - nStart);
    }

    // ********************************************************* Step 9: import blocks

    if (g_mapArgs.count("-loadblock"))
    {
        uiInterface.InitMessage(_("Importing blockchain data file."));

        for(string strFile : g_mapMultiArgs["-loadblock"])
        {
            FILE *file = fopen(strFile.c_str(), "rb");
            if (file)
                Tughlaq::LoadExternalBlockFile(file);
        }
        exit(0);
    }

    filesystem::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (filesystem::exists(pathBootstrap))
    {
        uiInterface.InitMessage(_("Importing bootstrap blockchain data file."));

        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file)
       	{
            filesystem::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
	    Tughlaq::LoadExternalBlockFile(file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        }
    }

    // ********************************************************* Step 10: load peers

    uiInterface.InitMessage(_("Loading addresses..."));
    printf("Loading addresses...\n");
    nStart = GetTimeMillis();
    CAddrMan& addrman = homeNode->getAddrMan();

    {
        CAddrDB adb;
        if (!adb.Read(addrman))
            printf("Invalid or missing peers.dat; recreating\n");
    }

    printf("Loaded %i addresses from peers.dat  %" PRId64 "ms\n",
           addrman.size(), GetTimeMillis() - nStart);

    // ********************************************************* Step 11: start node

    if (!Tughlaq::CheckDiskSpace())
        return false;

    RandAddSeedPerfmon();

    //// debug print
    printf("g_mapBlockIndex.size() = %" PRIszu "\n",   g_mapBlockIndex.size());
    printf("g_nBestHeight = %d\n",                     g_nBestHeight);
    printf("setKeyPool.size() = %" PRIszu "\n",        g_tughlaqWallet->setKeyPool.size());
    printf("mapWallet.size() = %" PRIszu "\n",         g_tughlaqWallet->mapWallet.size());
    printf("mapAddressBook.size() = %" PRIszu "\n",    g_tughlaqWallet->mapAddressBook.size());


    //mbt: The action now passes to net.cpp. StartNode is crucial function. It starts more threads like sockethandler and messagehandler threads.
    if (!homeNode->StartNode()) //action passes to net.cpp now.
        InitError(_("Error: could not start node"));
    else
        printf("\nNode Successfully started\n");

    if (fServer) NewThread(ThreadRPCServer, NULL);

    // InitRPCMining is needed here so getwork/getblocktemplate in the GUI debug console works properly.
    InitRPCMining();

    // Generate coins in the background
    if (g_tughlaqWallet)
    {
        GenerateTughlaq(GetBoolArg("-gen", false), g_tughlaqWallet);
	printf("\nGenerateTughlaq done\n");
    }
    // ********************************************************* Step 12: finished

    uiInterface.InitMessage(_("Done loading"));
    printf("Done loading\n");

    if (!strErrors.str().empty())
        return InitError(strErrors.str());

     // Add wallet transactions that aren't already in a block to mapTransactions
    g_tughlaqWallet->ReacceptWalletTransactions();

    return true;
}
