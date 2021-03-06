// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "bitcoinrpc.h"

#ifndef QT_GUI
#include "util.h"
#include "init.h"

#include "miniunz.h"
#include <curl/curl.h>
#endif

using namespace json_spirit;
using namespace std;
double dminDifficulty = 0.00000048; //standard scrypt^2 difficulty minimum

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, json_spirit::Object& entry);

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    if (blockindex == NULL)
    {
        if (g_pindexBest == NULL)
            return dminDifficulty;
        else if (g_pindexBest->pprev == NULL)
            return dminDifficulty;
        else if (g_pindexBest->pprev->pprev == NULL)
            return dminDifficulty;
        else
            blockindex = g_pindexBest->pprev;
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);
    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }
    return dDiff;
}

double GetPoWKHashPM()
{
    int nPoWInterval = 72;
    int64_t nTargetSpacingWorkMin = 30, nTargetSpacingWork = 30;

    CBlockIndex* pindex = g_pindexGenesisBlock;
    CBlockIndex* pindexPrevWork = g_pindexGenesisBlock;

    while (pindex)
    {
        int64_t nActualSpacingWork = pindex->GetBlockTime() - pindexPrevWork->GetBlockTime();
        nTargetSpacingWork = ((nPoWInterval - 1) * nTargetSpacingWork + nActualSpacingWork + nActualSpacingWork) / (nPoWInterval + 1);
        nTargetSpacingWork = max(nTargetSpacingWork, nTargetSpacingWorkMin);
        pindexPrevWork = pindex;
        pindex = pindex->pnext;
    }

    return (GetDifficulty() * 1024 * 4294.967296  / nTargetSpacingWork) * 60;  // 60= sec to min, 1024= standard scrypt work to scrypt^2
}

Object blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool fPrintTransactionDetail)
{
    Object result;
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    CMerkleTx txGen(block.vtx[0]);
    txGen.SetMerkleBranch(&block);
    result.push_back(Pair("confirmations", (int)txGen.GetDepthInMainChain()));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("mint", ValueFromAmount(blockindex->nMint)));
    result.push_back(Pair("time", (boost::int64_t)block.GetBlockTime()));
    result.push_back(Pair("nonce", (boost::uint64_t)block.nNonce));
    result.push_back(Pair("bits", HexBits(block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("blocktrust", leftTrim(blockindex->GetBlockTrust().GetHex(), '0')));
    result.push_back(Pair("chaintrust", leftTrim(blockindex->nChainTrust.GetHex(), '0')));
    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    if (blockindex->pnext)
        result.push_back(Pair("nextblockhash", blockindex->pnext->GetBlockHash().GetHex()));

    result.push_back(Pair("flags", strprintf("%s","proof-of-work")));
    result.push_back(Pair("proofhash", blockindex->GetBlockHash().GetHex()));
    Array txinfo;
    for (const CTransaction& tx : block.vtx)
    {
        if (fPrintTransactionDetail)
        {
            Object entry;

            entry.push_back(Pair("txid", tx.GetHash().GetHex()));
            TxToJSON(tx, 0, entry);

            txinfo.push_back(entry);
        }
        else
            txinfo.push_back(tx.GetHash().GetHex());
    }

    result.push_back(Pair("tx", txinfo));

    return result;
}

Value getbestblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getbestblockhash\n"
            "Returns the hash of the best block in the longest block chain.");

    return g_hashBestChain.GetHex();
}

Value getblockcount(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getblockcount\n"
            "Returns the number of blocks in the longest block chain.");

    return g_nBestHeight;
}


Value getdifficulty(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getdifficulty\n"
            "Returns the difficulty as a multiple of the minimum difficulty.");

    Object obj;
    obj.push_back(Pair("proof-of-work",        GetDifficulty()));
    return obj;
}


Value settxfee(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 1 || AmountFromValue(params[0]) < MIN_TX_FEE)
        throw runtime_error(
            "settxfee <amount>\n"
            "<amount> is a real and is rounded to the nearest 0.01");

    nTransactionFee = AmountFromValue(params[0]);
    nTransactionFee = (nTransactionFee / CENT) * CENT;  // round to cent

    return true;
}

Value getrawmempool(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getrawmempool\n"
            "Returns all transaction ids in memory pool.");

    vector<uint256> vtxid;
    g_mempool.queryHashes(vtxid);

    Array a;
    BOOST_FOREACH(const uint256& hash, vtxid)
        a.push_back(hash.ToString());

    return a;
}

Value getblockhash(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getblockhash <index>\n"
            "Returns hash of block in best-block-chain at <index>.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > g_nBestHeight)
        throw runtime_error("Block number out of range.");

    CBlockIndex* pblockindex = Tughlaq::FindBlockByHeight(nHeight);
    return pblockindex->phashBlock->GetHex();
}

Value getblock(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblock <hash> [txinfo]\n"
            "txinfo optional to print more detailed tx info\n"
            "Returns details of a block with given block-hash.");

    std::string strHash = params[0].get_str();
    uint256 hash(strHash);

    if (g_mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = g_mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}

Value getblockbynumber(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getblockbynumber <number> [txinfo]\n"
            "txinfo optional to print more detailed tx info\n"
            "Returns details of a block with given block-number.");

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > g_nBestHeight)
        throw runtime_error("Block number out of range.");

    CBlock block;
    CBlockIndex* pblockindex = g_mapBlockIndex[g_hashBestChain];
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;

    uint256 hash = *pblockindex->phashBlock;

    pblockindex = g_mapBlockIndex[hash];
    block.ReadFromDisk(pblockindex, true);

    return blockToJSON(block, pblockindex, params.size() > 1 ? params[1].get_bool() : false);
}

// ppcoin: get information of sync-checkpoint
Value getcheckpoint(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getcheckpoint\n"
            "Show info of synchronized checkpoint.\n");

    Object result;
    const CBlockIndex* pindexCheckpoint = Checkpoints::AutoSelectSyncCheckpoint();

    result.push_back(Pair("synccheckpoint", pindexCheckpoint->GetBlockHash().ToString().c_str()));
    result.push_back(Pair("height", pindexCheckpoint->nHeight));
    result.push_back(Pair("timestamp", DateTimeStrFormat(pindexCheckpoint->GetBlockTime()).c_str()));
    result.push_back(Pair("policy", "rolling"));

    return result;
}

#ifndef QT_GUI
static size_t write_data(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

int DownloadFile(std::string url, boost::filesystem::path target_file_path)
{
    int err = 0;

    printf("bootstrap: Downloading blockchain from %s. \n", url.c_str());

    CURL *curlHandle = curl_easy_init();
    curl_easy_setopt(curlHandle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curlHandle, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curlHandle, CURLOPT_WRITEFUNCTION, write_data);

    FILE *file = fopen((const char*)(target_file_path.c_str()), "wb"); //Gautam
    if(file)
    {
        curl_easy_setopt(curlHandle, CURLOPT_WRITEDATA, file);
        CURLcode curl_err = curl_easy_perform(curlHandle);
        if (curl_err != CURLE_OK)
            printf("bootstrap: Error downloading from %s. Error: %s.\n", url.c_str(), curl_easy_strerror(curl_err));
        fclose(file);
        err = (int)curl_err;
    }
    else
    {
        printf("bootstrap: Download error: Unable to open output file for writing: %s.\n", target_file_path.c_str());
        err = -1;
    }

    curl_easy_cleanup(curlHandle);

    return err;
}

int ExtractBootstrapFile(boost::filesystem::path& pathBootstrap)
{
    printf("bootstrap: Extracting bootstrap file\n");
    if (!boost::filesystem::exists(pathBootstrap)) {
        printf("bootstrap: Bootstrap file doesn't exist!\n");
        return -1;
    }

    const char * zipfilename = (const char*)(pathBootstrap.c_str()); //Gautam
    unzFile uf;
#ifdef USEWIN32IOAPI
    zlib_filefunc64_def ffunc;
    fill_win32_filefunc64A(&ffunc);
    uf = unzOpen2_64(zipfilename, &ffunc);
#else
    uf = unzOpen64(zipfilename);
#endif

    if (uf == NULL)
    {
        printf("bootstrap: Cannot open downloaded file: %s\n", zipfilename);
        return -2;
    }

    int unzip_err = zip_extract_all(uf, GetDataDir(), "bootstrap");
    if (unzip_err != UNZ_OK)
    {
        printf("bootstrap: Unzip failed\n");
        return -3;
    }

    printf("bootstrap: Unzip successful\n");

    if (!boost::filesystem::exists(GetDataDir() / "bootstrap" / "blk0001.dat") ||
        !boost::filesystem::exists(GetDataDir() / "bootstrap" / "txleveldb"))
    {
        printf("bootstrap: Downloaded zip file did not contain all necessary files!\n");
        return -4;
    }

    return 0;
}

Value bootstrap(const Array& params, bool fHelp)
{
    printf("\nmbt: reached rpcblockchain.bootstrap\n");

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "bootstrap [overwrite_tughlaqconf=false]\n"
            "Download blockchain and optionally a current tughlaq.conf from www.kanchiworld.com.\n"
            "Daemon exits when finished."
        );

    if (params.size() == 1)
    {
        fBootstrapConfig = params[0].get_bool();
    }

    Object result;
    boost::filesystem::path pathBootstrapZip = GetDataDir() / "Tughlaq-699.jpg";
    int err = DownloadFile("https://sites.google.com/a/kanchiworld.com/kanchi-wo/5-minutes-fairy-tales-pics/IMAG0699.jpg?attredirects=0&d=1", pathBootstrapZip);

    if (err != 0)
    {
        printf("mbt: rpcblockchain.bootstrap: Download failed!\n");
        result.push_back(Pair("success", false));
        result.push_back(Pair("error", "Download failed"));
        result.push_back(Pair("error_code", err));
        return result;
    }
    printf("mbt: rpcblockchain.bootstrap: Download successful\n");

    /* mbt - no need to unzip
    err = ExtractBootstrapFile(pathBootstrapZip);
    if (err != 0)
    {
        printf("bootstrap: Extracting failed!\n");
        result.push_back(Pair("success", false));
        result.push_back(Pair("error", "Extracting failed"));
        result.push_back(Pair("error_code", err));
        return result;
    }
    */

    fBootstrapTurbo = true;
    StartShutdown();

    result.push_back(Pair("success", true));
    result.push_back(Pair("comment", "Bootstrap successful; tughlaqd has been stopped, please restart."));

    return result;
}
#endif

