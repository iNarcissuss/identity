#include "Output.h"
#include "Parser.h"

extern "C" {
#include "ac/ac.h"
}

#include <string>
#include <vector>

#include <boost/program_options.hpp>
#include <nlohmann/json.hpp>

using std::cout;
using std::endl;
using std::string;
using std::vector;

namespace po = boost::program_options;

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

int main(int argc, char** argv)
{
	// Command line options parsing
	po::options_description description("Allowed options");
	description.add_options()
	    ("help", "This help message")
	    ("pcap", po::value<string>(), "Set the input PCAP filename")
	;

	po::variables_map args;
	po::store (po::command_line_parser (argc, argv).options(description).run(), args);
  po::notify (args);

	if (args.count("help")) {
	    cout << description << "\n";
	    return 1;
	}

	string pcapFilename;
	if (args.count("pcap")) {
		pcapFilename = args["pcap"].as<string>();
	} else {
	    pcapFilename = "capture.pcap";
	}
	// Parse network payload and store to frameVector
  // vector<Frame> frameVector;
  // csvParser(frameVector, "./charis2.csv");

  vector<Frame> frameVector2;
  Parser parser;
  parser.pcap(frameVector2, pcapFilename);

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
        cout << "Identity spoofing attack, " << it.mId << ", " << it.mTimestamp << ", " << it.mSource_ip << ", "
             << it.mDest_ip << ", " << pattern[results.pattern] << ", " << results.location << endl;

        outFile << "Identity spoofing attack, " << it.mId << ", " << it.mTimestamp << ", " << it.mSource_ip << ", "
                << it.mDest_ip << ", " << pattern[results.pattern] << ", " << results.location << endl;

        outputData["Activity"][outputDataCounter]["Alert type"] = "Identity spoofing attack";
        outputData["Activity"][outputDataCounter]["Source IP"] = it.mSource_ip;
        outputData["Activity"][outputDataCounter]["Destination IP"] = it.mDest_ip;
        outputData["Activity"][outputDataCounter]["Timestamp"] = it.mTimestamp;
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
  Output::storeJSON<nlohmann::json>(outputData);

  // for (auto& it : frameVector) {
  // 	cout << it.mId << " " << it.mProtocol << " " << it.mSource_ip << " " << it.mSource_port << " " << it.mDest_ip << " " << it.mDest_port << " " << it.mPayload << endl << endl;
  // 	if (it.mId == "1270") break;
  // }

  // for (auto& it : frameVector2) {
  // 	if(it.mProtocol == "TCP")cout << it.mId << " " << it.mProtocol << " " << it.mSource_ip << " " << it.mSource_port << " " << it.mDest_ip << " " << it.mDest_port << " " << it.mPayload << endl << endl;
  // }

  return 0;
}
