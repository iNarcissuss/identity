#pragma once

#include <fstream>
#include <iomanip>
#include <string>
#include <vector>

#include <pcapplusplus/ArpLayer.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>

using std::string;
using std::vector;

struct Frame {
  Frame(string id) : mId(id){};

  Frame(string id, string timestamp, string source_ip, string source_mac, string dest_ip, string dest_mac,
        string length, string protocol, string source_port, string dest_port, string payload)
    : mId(id),
      mTimestamp(timestamp),
      mSource_ip(source_ip),
      mSource_mac(source_mac),
      mDest_ip(dest_ip),
      mDest_mac(dest_mac),
      mLength(length),
      mProtocol(protocol),
      mSource_port(source_port),
      mDest_port(dest_port),
      mPayload(payload){};
  string mId;
  string mTimestamp;
  string mSource_ip;
  string mSource_mac;
  string mDest_ip;
  string mDest_mac;
  string mLength;
  string mProtocol;
  string mSource_port = "";
  string mDest_port = "";
  string mPayload = "";

  unsigned int mTotalLength = 0;
};

class Parser
{
 public:
  Parser();

  void pcap(vector<Frame>& frameVector, const string& filename);

  void csv(vector<Frame>& frameVector, const string& filename);

 private:
  std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType);

  std::string printTcpFlags(pcpp::TcpLayer* tcpLayer);
};
