#include <Parser.h>

#include <iostream>
#include <sstream>

#include <arpa/inet.h>
#include <sys/time.h>

#include <nlohmann/json.hpp>

using std::cout;
using std::endl;
using std::ifstream;
using std::stringstream;

Parser::Parser() {}
std::string Parser::getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
  switch (protocolType) {
    case pcpp::Ethernet:
      return "Ethernet";
    case pcpp::IPv4:
      return "IPv4";
    case pcpp::TCP:
      return "TCP";
    case pcpp::UDP:
      return "UDP";
    case pcpp::ARP:
      return "ARP";
    case pcpp::DNS:
      return "DNS";
    case pcpp::HTTPRequest:
    case pcpp::HTTPResponse:
      return "HTTP";
    default:
      return "Unknown";
  }
}

std::string Parser::printTcpFlags(pcpp::TcpLayer* tcpLayer)
{
  std::string result = "";
  if (tcpLayer->getTcpHeader()->synFlag == 1)
    result += "SYN ";
  if (tcpLayer->getTcpHeader()->ackFlag == 1)
    result += "ACK ";
  if (tcpLayer->getTcpHeader()->pshFlag == 1)
    result += "PSH ";
  if (tcpLayer->getTcpHeader()->cwrFlag == 1)
    result += "CWR ";
  if (tcpLayer->getTcpHeader()->urgFlag == 1)
    result += "URG ";
  if (tcpLayer->getTcpHeader()->eceFlag == 1)
    result += "ECE ";
  if (tcpLayer->getTcpHeader()->rstFlag == 1)
    result += "RST ";
  if (tcpLayer->getTcpHeader()->finFlag == 1)
    result += "FIN ";

  return result;
}

void Parser::pcap(vector<Frame>& frameVector, const string& filename)
{
  pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader(filename.c_str());

  // verify that a reader interface was indeed created
  if (reader == NULL) {
    cout << "Cannot determine pcap reader for file type" << endl;
    exit(1);
  }

  // open the reader for reading
  if (!reader->open()) {
    printf("Cannot open pcap file for reading\n");
    exit(1);
  }

  // Parse all packets in pcap file
  unsigned int packetCounter = 0;
  while (1) {
    // Create new frame
    Frame frame(std::to_string(packetCounter++));

    pcpp::RawPacket rawPacket;
    // Break the loop when a next file could not be found
    if (!reader->getNextPacket(rawPacket)) {
      break;
    }

    // Retrieve raw packet timestamp and convert to a human readable format
    timeval tv = rawPacket.getPacketTimeStamp();
    stringstream ss;
    ss << tv.tv_sec;
    ss << '.';
    ss << tv.tv_usec;
    // cout << tv.tv_sec << '.' << tv.tv_usec << endl;
    // time_t nowtime;
    // nowtime = tv.tv_usec;
    // int milli = tv.tv_usec / 1000;
    // char buffer[80];
    // strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", localtime(&tv.tv_sec));
    // char currentTime[84] = "";
    // sprintf(currentTime, "%s:%d", buffer, milli);
    frame.mTimestamp = ss.str();

    // parse the raw packet into a parsed packet
    pcpp::Packet parsedPacket(&rawPacket);

    // first let's go over the layers one by one and find out its type, its total length, its header length and its
    // payload length
    for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer()) {
      // printf("%i] Layer type: %s %i; Total data: %d [bytes]; Layer data: %d [bytes]; Layer payload: %d [bytes]\n",
      // packetCounter,
      //    getProtocolTypeAsString(curLayer->getProtocol()).c_str(), // get layer type
      //    curLayer->getProtocol(),
      //    (int)curLayer->getDataLen(),                              // get total length of the layer
      //    (int)curLayer->getHeaderLen(),                            // get the header length of the layer
      //    (int)curLayer->getLayerPayloadSize());                    // get the payload length of the layer (equals
      //    total length minus header length)

      frame.mTotalLength += (int)curLayer->getDataLen();
    }

    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
    if (ipLayer != NULL) {
      // printf("\nSource IP address: %s\n", ipLayer->getSrcIpAddress().toString().c_str());
      // printf("Destination IP address: %s\n", ipLayer->getDstIpAddress().toString().c_str());
      // printf("IP ID: 0x%X\n", ntohs(ipLayer->getIPv4Header()->ipId));
      // printf("TTL: %d\n", ipLayer->getIPv4Header()->timeToLive);

      frame.mSource_ip = ipLayer->getSrcIpAddress().toString().c_str();
      frame.mDest_ip = ipLayer->getDstIpAddress().toString().c_str();
    }

    pcpp::DnsLayer* dnsLayer = parsedPacket.getLayerOfType<pcpp::DnsLayer>();
    if (dnsLayer != NULL) {
      // printf("\nSource IP address: %s\n", ipLayer->getSrcIpAddress().toString().c_str());
      // printf("Destination IP address: %s\n", ipLayer->getDstIpAddress().toString().c_str());
      // printf("IP ID: 0x%X\n", ntohs(ipLayer->getIPv4Header()->ipId));
      // printf("TTL: %d\n", ipLayer->getIPv4Header()->timeToLive);

      frame.mProtocol = "DNS";
    }

    pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    if (tcpLayer != NULL) {
      // printf("\nSource TCP port: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portSrc));
      // printf("Destination TCP port: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->portDst));
      // printf("Window size: %d\n", (int)ntohs(tcpLayer->getTcpHeader()->windowSize));
      // printf("TCP flags: %s\n", printTcpFlags(tcpLayer).c_str());

      frame.mSource_port = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
      frame.mDest_port = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
      frame.mProtocol = "TCP";
    }

    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    if (udpLayer != NULL) {
      frame.mSource_port = (int)ntohs(udpLayer->getUdpHeader()->portSrc);
      frame.mDest_port = (int)ntohs(udpLayer->getUdpHeader()->portDst);
      frame.mProtocol = "UDP";
    }

    pcpp::IcmpLayer* icmpLayer = parsedPacket.getLayerOfType<pcpp::IcmpLayer>();
    if (icmpLayer != NULL) {
      frame.mProtocol = "ICMP";
    }

    pcpp::ArpLayer* arpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();
    if (arpLayer != NULL) {
      frame.mProtocol = "ARP";
    }

    pcpp::PayloadLayer* payloadLayer = parsedPacket.getLayerOfType<pcpp::PayloadLayer>();
    if (payloadLayer != NULL) {
      // cout << "Payload: " << payloadLayer->getPayloadLen() << " " << payloadLayer->getPayload() << endl;
      uint8_t payloadArray[payloadLayer->getPayloadLen()];

      std::ostringstream convert;
      // Sanitize the packet payload
      for (int i = 0; i < payloadLayer->getPayloadLen(); i++) {
        if (payloadLayer->getPayload()[i] >= 32 && payloadLayer->getPayload()[i] <= 126) {
          convert << (char)payloadLayer->getPayload()[i];
        } else {
          convert << '.';
        }
      }

      frame.mPayload = convert.str();
      // cout << payload << endl;
    }
    frameVector.push_back(frame);
  }

  // Close the file reader, we don't need it anymore
  reader->close();

  // Statistics!
  cout << "Parsed " << frameVector.size() << " frames" << endl;

  int udpCounter = 0;
  int tcpCounter = 0;
  int icmpCounter = 0;
  int arpCounter = 0;
  int unknownCounter = 0;
  for (auto& i : frameVector) {
    if (i.mProtocol == "UDP") {
      udpCounter++;
    } else if (i.mProtocol == "TCP") {
      tcpCounter++;
    } else if (i.mProtocol == "ICMP") {
      icmpCounter++;
    } else if (i.mProtocol == "ARP") {
      arpCounter++;
    } else {
      unknownCounter++;
    }
  }
  cout << "Parsed " << udpCounter << " UDP " << tcpCounter << " TCP " << icmpCounter << " ICMP " << arpCounter
       << " ARP and " << unknownCounter << " unknown protocol messages" << endl;

  double size = 0;
  for (auto& i : frameVector) {
    if (i.mProtocol == "TCP") {
      size += i.mPayload.length();
    }
  }

  cout << "Average payload size of all TCP packets: " << size / tcpCounter << " bytes" << endl;
}

void Parser::csv(vector<Frame>& frameVector, const string& filename)
{
  ifstream infile(filename);
  string line = "";

  // Parse each new line
  while (getline(infile, line, '\n')) {
    stringstream strstr(line);
    // cout << line << endl; return 1;

    // Parse the first 10 comma-delimited entries of each line
    vector<string> wordVector(11);
    for (int i = 0; i < wordVector.size(); i++) {
      string word = "";
      if (i != wordVector.size() - 1) {
        getline(strstr, word, ',');
      } else {
        // The last entry is the payload, should be copied as is to frame
        getline(strstr, word);
      }
      wordVector.at(i) = word;
    }

    // Store the entries to a frame and push it to a vector
    frameVector.push_back(Frame(wordVector.at(0), wordVector.at(1), wordVector.at(2), wordVector.at(3),
                                wordVector.at(4), wordVector.at(5), wordVector.at(6), wordVector.at(7),
                                wordVector.at(8), wordVector.at(9), wordVector.at(10)));
  }

  // Statistics!
  cout << "Parsed " << frameVector.size() << " frames" << endl;

  int udpCounter = 0;
  int tcpCounter = 0;
  int icmpCounter = 0;
  int arpCounter = 0;
  int unknownCounter = 0;
  for (auto& i : frameVector) {
    if (i.mProtocol == "UDP") {
      udpCounter++;
    } else if (i.mProtocol == "TCP") {
      tcpCounter++;
    } else if (i.mProtocol == "ICMP") {
      icmpCounter++;
    } else if (i.mProtocol == "ARP") {
      arpCounter++;
    } else {
      unknownCounter++;
    }
  }
  cout << "Parsed " << udpCounter << " UDP " << tcpCounter << " TCP " << icmpCounter << " ICMP " << arpCounter
       << " ARP and " << unknownCounter << " unknown protocol messages" << endl;

  double size = 0;
  for (auto& i : frameVector) {
    if (i.mProtocol == "TCP") {
      size += i.mPayload.length();
    }
  }
  cout << "Average payload size of all TCP packets: " << size / tcpCounter << " bytes" << endl;
}
