// g++ -std=c++11 -o csvParser csvParser.cpp  && ./csvParser

extern "C" {
#include "ac/ac.h"
}

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
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/HttpLayer.h>

using std::cout;
using std::endl;
using std::ifstream;
using std::string;
using std::stringstream;
using std::vector;

struct Frame {
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
  string mSource_port;
  string mDest_port;
  string mPayload;
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
	case pcpp::HTTPRequest:
	case pcpp::HTTPResponse:
		return "HTTP";
	default:
		return "Unknown";
	}
}

int main(int argc, char** argv)
{
	// Parse network payload and store to frameVector
  vector<Frame> frameVector;
  csvParser(frameVector, "./charis2.csv");

  // Parse configuration file with IPs and usernames
  std::ifstream ifs("input.json");
  nlohmann::json data;
  ifs >> data;

  // Store IPs/usernames to credentialsVector
  vector<Credentials> credentialsVector;
  for (unsigned int i = 0; i < data["Credentials"].size(); i++ ) {
    string ip = data["Credentials"][i]["IP"];
    string username = data["Credentials"][i]["Username"];

    credentialsVector.push_back(Credentials(ip, username));
  }

  //Open output file for writing
  std::ofstream outFile("output.csv");

  // Deep packet inspection
  // For every packet in the payload
  cout << "Inspecting TCP packets with actual payload" << endl << endl;

  cout << "Alert type, Frame ID, Source IP, Destination IP, Username, Frame location" << endl;
  outFile << "Alert type, Frame ID, Source IP, Destination IP, Username, Frame location" << endl;
  for (auto& it : frameVector) {
    // Inspect only TCP packets with actual payload
    if (it.mProtocol == "TCP" && std::stod(it.mLength) > 96) {
      const int m2 = 7;
      const int alphabet2 = 256;
      const int n2 = it.mPayload.length();
      const int p_size2 = 2;

      // Allocate text and pattern
      unsigned char* text2 = (unsigned char*)malloc(sizeof(unsigned char) * n2);

      if (text2 == NULL) {
        printf("Failed to allocate array\n");
      }

      unsigned char** pattern2 = (unsigned char**)malloc(p_size2 * sizeof(unsigned char*));

      if (pattern2 == NULL) {
        printf("Failed to allocate array!\n");
      }

      for (int i = 0; i < p_size2; i++) {
        pattern2[i] = (unsigned char*)malloc(m2 * sizeof(unsigned char));

        if (pattern2[i] == NULL)
          printf("Failed to allocate array!\n");
      }

      // Copy credentialsVector to the pattern array
      for (int i = 0; i < p_size2; i++) {
        // Don't copy over though the username associated with the current source OR destination ip
        if (it.mSource_ip != credentialsVector.at(i).mSource_ip &&
            it.mDest_ip != credentialsVector.at(i).mSource_ip) {
          std::copy (credentialsVector.at(i).mUsername.begin(), credentialsVector.at(i).mUsername.end(), pattern2[i]);
          pattern2[i][m2] = '\0';
        }
      }

      if ( n2 < it.mPayload.end() - it.mPayload.begin()) {
        cout << "ERRRORRRRRR" << endl;
        break;
      }

      for (int i = 0; i < n2; i++) {
          if (text2[i] < 0 || text2[i] >= alphabet2) {
          cout << "ERRRORRRRRR22222" << endl;
          break;
        }
      }

			std::copy( it.mPayload.begin(), it.mPayload.end(), text2 );
      text2[n2 - 1] = '\0';

      struct Results results = multiac(pattern2, m2, text2, n2, p_size2, alphabet2);
      if (results.matches > 0) {
        cout << "Identity spoofing attack, " << it.mId << ", " << it.mSource_ip << ", " << it.mDest_ip << ", "
             << pattern2[results.pattern] << ", " << results.location << endl;
        outFile << "Identity spoofing attack, " << it.mId << ", " << it.mSource_ip << ", " << it.mDest_ip << ", "
             << pattern2[results.pattern] << ", " << results.location << endl;
      }

      free(text2);

      for (int i = 0; i < p_size2; i++) {
        free(pattern2[i]);
      }

      free(pattern2);
    }
  }
  // Close output file
  outFile.close();

  pcpp::IFileReaderDevice* reader = pcpp::IFileReaderDevice::getReader("capture2.pcap");

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

  pcpp::RawPacket rawPacket;
	if (!reader->getNextPacket(rawPacket)) {
		printf("Couldn't read the first packet in the file\n");
		exit(1);
	}

	// close the file reader, we don't need it anymore
	reader->close();

	// parse the raw packet into a parsed packet
	pcpp::Packet parsedPacket(&rawPacket);

	// first let's go over the layers one by one and find out its type, its total length, its header length and its payload length
	for (pcpp::Layer* curLayer = parsedPacket.getFirstLayer(); curLayer != NULL; curLayer = curLayer->getNextLayer())
	{
		printf("Layer type: %s; Total data: %d [bytes]; Layer data: %d [bytes]; Layer payload: %d [bytes]\n",
				getProtocolTypeAsString(curLayer->getProtocol()).c_str(), // get layer type
				(int)curLayer->getDataLen(),                              // get total length of the layer
				(int)curLayer->getHeaderLen(),                            // get the header length of the layer
				(int)curLayer->getLayerPayloadSize());                    // get the payload length of the layer (equals total length minus header length)
	}

	pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
	if (ipLayer == NULL) {
		printf("Something went wrong, couldn't find IPv4 layer\n");
	} else {
		printf("\nSource IP address: %s\n", ipLayer->getSrcIpAddress().toString().c_str());
		printf("Destination IP address: %s\n", ipLayer->getDstIpAddress().toString().c_str());
		printf("IP ID: 0x%X\n", ntohs(ipLayer->getIPv4Header()->ipId));
		printf("TTL: %d\n", ipLayer->getIPv4Header()->timeToLive);
	}

	pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
	if (tcpLayer == NULL) {
		printf("Something went wrong, couldn't find TCP layer\n");
	}

  return 0;
}
