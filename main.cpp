// g++ -std=c++11 -o csvParser csvParser.cpp  && ./csvParser

extern "C" {
#include "ac/ac.h"
}

#include <array>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/ArpLayer.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/PayloadLayer.h>

using std::array;
using std::cout;
using std::endl;
using std::ifstream;
using std::string;
using std::stringstream;
using std::vector;

struct Frame {
	Frame(string id)
    : mId(id){};

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

class Credentials {
public:
  Credentials(string source_ip, string username) :
              mSource_ip(source_ip), mUsername(username){};
	string mSource_ip;
	string mUsername;
};

struct Results multiac(unsigned char** pattern, int m, unsigned char* text, int n, int p_size, int alphabet)
{
  struct ac_table* table = preproc_ac(pattern, m, p_size, alphabet);

  struct Results results = search_ac(text, n, table);

  free_ac(table, alphabet);

  return results;
}

std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
	switch (protocolType)
	{
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

std::string printTcpFlags(pcpp::TcpLayer* tcpLayer)
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

void pcapParser(vector<Frame>& frameVector, const string& filename)
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
  while(1) {
    // cout << "Packet " << packetCounter << endl;

	  pcpp::RawPacket rawPacket;
	  // Break the loop when a next file could not be found
		if (!reader->getNextPacket(rawPacket)) {
			break;
		}

		// Create new frame
		Frame frame(std::to_string(packetCounter));
		packetCounter++;

		// parse the raw packet into a parsed packet
		pcpp::Packet parsedPacket(&rawPacket);

		// first let's go over the layers one by one and find out its type, its total length, its header length and its payload length
		for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer()) {
			// printf("%i] Layer type: %s %i; Total data: %d [bytes]; Layer data: %d [bytes]; Layer payload: %d [bytes]\n", packetCounter,
			// 		getProtocolTypeAsString(curLayer->getProtocol()).c_str(), // get layer type
			// 		curLayer->getProtocol(),
			// 		(int)curLayer->getDataLen(),                              // get total length of the layer
			// 		(int)curLayer->getHeaderLen(),                            // get the header length of the layer
			// 		(int)curLayer->getLayerPayloadSize());                    // get the payload length of the layer (equals total length minus header length)

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
			//cout << "Payload: " << payloadLayer->getPayloadLen() << " " << payloadLayer->getPayload() << endl;
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

void csvParser(vector<Frame>& frameVector, const string& filename)
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

/// Stores the JSON structure in <data> locally
template <typename T>
static void storeJSON(const T& data)
{
  std::string filename ="output.json";
  std::ofstream fileOutput(filename);
  if (!fileOutput) {
    cout << "Cannot create file: "  << filename << endl;
  }
  cout << "Saving the output in the file: "  << filename << endl;

  fileOutput << std::setw(2) << data << std::endl;
  fileOutput.close();
}

int main(int argc, char** argv)
{
	// Parse network payload and store to frameVector
  // vector<Frame> frameVector;
  // csvParser(frameVector, "./charis2.csv");

  vector<Frame> frameVector2;
  pcapParser(frameVector2, "capture.pcap");

  // Parse configuration file with IPs and usernames
  std::ifstream ifs("input.json");
  nlohmann::json inputData;
  ifs >> inputData;

  // Store IPs/usernames to credentialsVector
  vector<Credentials> credentialsVector;
  for (unsigned int i = 0; i < inputData["Credentials"].size(); i++ ) {
    string ip = inputData["Credentials"][i]["IP"];
    string username = inputData["Credentials"][i]["Username"];

    credentialsVector.push_back(Credentials(ip, username));
  }

  //Open output file for writing
  std::ofstream outFile("output.csv");
  nlohmann::json outputData;
  int outputDataCounter = 0;

  // Deep packet inspection
  // For every packet in the payload
  cout << "Inspecting TCP packets with actual payload" << endl << endl;

  cout << "Alert type, Frame ID, Source IP, Destination IP, Username, Frame location" << endl;
  outFile << "Alert type, Frame ID, Source IP, Destination IP, Username, Frame location" << endl;
  for (auto& it : frameVector2) {
    // Inspect only TCP packets with actual payload
    if (it.mProtocol == "TCP" && it.mPayload.length() > 0) {
      const int m = 7;
      const int alphabet = 256;
      const int n = it.mPayload.length();
      const int p_size = inputData["Credentials"].size();

      // Allocate text and pattern
      unsigned char* text = (unsigned char*)malloc(sizeof(unsigned char) * n);

      if (text == NULL) {
        printf("Failed to allocate array\n");
      }

      unsigned char** pattern = (unsigned char**)malloc(p_size * sizeof(unsigned char*));

      if (pattern == NULL) {
        printf("Failed to allocate array!\n");
      }

      for (int i = 0; i < p_size; i++) {
        pattern[i] = (unsigned char*)malloc(m * sizeof(unsigned char));

        if (pattern[i] == NULL)
          printf("Failed to allocate array!\n");
      }

      // Copy credentialsVector to the pattern array and pass them to the C algorithm
      for (int i = 0; i < p_size; i++) {
        // Don't copy over though the username associated with the current source OR destination ip
        if (it.mSource_ip != credentialsVector.at(i).mSource_ip &&
            it.mDest_ip != credentialsVector.at(i).mSource_ip) {
          std::copy (credentialsVector.at(i).mUsername.begin(), credentialsVector.at(i).mUsername.end(), pattern[i]);
          pattern[i][m] = '\0';
        }
      }

			std::copy( it.mPayload.begin(), it.mPayload.end(), text );
      text[n - 1] = '\0';

      struct Results results = multiac(pattern, m, text, n, p_size, alphabet);
      if (results.matches > 0) {
        cout << "Identity spoofing attack, " << it.mId << ", " << it.mSource_ip << ", " << it.mDest_ip << ", "
             << pattern[results.pattern] << ", " << results.location << endl;
        outFile << "Identity spoofing attack, " << it.mId << ", " << it.mSource_ip << ", " << it.mDest_ip << ", "
             << pattern[results.pattern] << ", " << results.location << endl;
        outputData["Activity"][outputDataCounter]["Alert type"] = "Identity spoofing attack";
        outputData["Activity"][outputDataCounter]["Source IP"] = it.mSource_ip;
        outputData["Activity"][outputDataCounter]["Destination IP"] = it.mDest_ip;
        //outputData["Activity"][outputDataCounter]["Username"] = pattern[results.pattern];
        outputDataCounter++;
      }

      // Free pattern and text arrays
      free(text);

      for (int i = 0; i < p_size; i++) {
        free(pattern[i]);
      }

      free(pattern);
    }
  }
  // Close output file
  outFile.close();
  storeJSON<nlohmann::json>(outputData);

  // for (auto& it : frameVector) {
  // 	cout << it.mId << " " << it.mProtocol << " " << it.mSource_ip << " " << it.mSource_port << " " << it.mDest_ip << " " << it.mDest_port << " " << it.mPayload << endl << endl;
  // 	if (it.mId == "1270") break;
  // }

  // for (auto& it : frameVector2) {
  // 	if(it.mProtocol == "TCP")cout << it.mId << " " << it.mProtocol << " " << it.mSource_ip << " " << it.mSource_port << " " << it.mDest_ip << " " << it.mDest_port << " " << it.mPayload << endl << endl;
  // }

  return 0;
}
