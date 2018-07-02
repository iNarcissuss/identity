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

void usage(void)
{
  printf(
    "Smatcher - Sequential two dimensional pattern matching toolkit using multiple pattern matching algorithms.\n");
  printf("Usage: <multiple algorithm> <2d algorithm> -m <m> -p_size <p_size> -n <n> -alphabet <alphabet>\n");
  printf("-h,--help,\t\t print this help message\n");
  printf("-c,\t\t create the data files\n");

  exit(0);
}

// Load multiple patterns and single texts
void load_files(unsigned char** pattern, unsigned char* text, int m, int n, const string& pattern_filename,
                const string& text_filename, int p_size)
{
  // Pattern loading
  FILE* fp = fopen(pattern_filename.c_str(), "r");

  if (fp == NULL) {
    printf("Could not open file\n");
  }

  // for( i = 0; i < p_size; i++ )
  //	fscanf( fp, "%s\n", &pattern[i][0] );

  for (int j = 0; j < p_size; j++) {
    for (int i = 0; i < m; i++)
      pattern[j][i] = fgetc(fp);

    // Dummy pull to discard "\n" at the end of each pattern
    fgetc(fp);
  }

  fclose(fp);

  // Text loading
  fp = fopen(text_filename.c_str(), "r");

  if (fp == NULL) {
    printf("helper_lib: could not open file\n");
  }

  for (int i = 0; i < n; i++) {
    text[i] = fgetc(fp);
  }

  fclose(fp);
}

int multiac(unsigned char** pattern, int m, unsigned char* text, int n, int p_size, int alphabet)
{
  struct ac_table* table = preproc_ac(pattern, m, p_size, alphabet);

  int matches = search_ac(text, n, table);

  free_ac(table, alphabet);

  //printf("search_ac matches \t%i\n", matches);

  return matches;
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

  // for (auto& i : frameVector) {
  // 	if (i.mProtocol == "TCP" && std::stod(i.mLength) > 96) {
  // 		cout << i.mId << " " << i.mLength << " " << i.mSource_port << " " << i.mDest_port << " " << i.mPayload << endl
  // <<
  // endl;
  // 	}
  // }
}

int main(int argc, char** argv)
{
  vector<Frame> frameVector;
  csvParser(frameVector, "../charis2.csv");

  int m = 0, p_size = 0, n = 0, alphabet = 0, B = 3, create_data = 0;

  // Scan command line arguments
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
      usage();

    if (strcmp(argv[i], "-m") == 0) {
      m = atoi(argv[i + 1]);
    }

    if (strcmp(argv[i], "-n") == 0) {
      n = atoi(argv[i + 1]);
    }

    if (strcmp(argv[i], "-p_size") == 0) {
      p_size = atoi(argv[i + 1]);
    }

    if (strcmp(argv[i], "-alphabet") == 0) {
      alphabet = atoi(argv[i + 1]);
    }

    if (strcmp(argv[i], "-c") == 0) {
      create_data = 1;
    }
  }

  if (m == 0 || n == 0 || p_size == 0 || alphabet == 0) {
    usage();
  }

  if (p_size > 100000) {
    printf("Only up to 100.000 patterns are supported\n");
  }

  // Determine path of pattern and text based on n
  const string pattern_filename = "pattern.txt";
  const string text_filename = "world192.txt";

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

  load_files(pattern, text, m, n, pattern_filename, text_filename, p_size);

  // AC implementation
  if (strcmp(argv[1], "ac") == 0) {
    multiac(pattern, m, text, n, p_size, alphabet);
  }

  free(text);

  for (int i = 0; i < p_size; i++) {
    free(pattern[i]);
  }

  free(pattern);

  vector<Credentials> credentialsVector;
  credentialsVector.push_back(Credentials("160.40.51.245", "skype"));
  credentialsVector.push_back(Credentials("160.40.51.244", "osoft"));


  // Deep packet inspection
  // For every packet in the payload
  cout << "Inspecting TCP packets with actual payload" << endl << endl;

  cout << "Alert type, Frame ID, Source IP, Destination IP, Username" << endl;
  for (auto& it : frameVector) {
    // Inspect only TCP packets with actual payload
    if (it.mProtocol == "TCP" && std::stod(it.mLength) > 96) {
      const int m2 = 5;
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

      // Fill pattern list with real usernames
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

      int matches = multiac(pattern2, m2, text2, n2, p_size2, alphabet2);
      if (matches > 0) {
        cout << "Attack detected, " << it.mId << ", " << it.mSource_ip << ", " << it.mDest_ip << endl;
      }

      free(text2);

      for (int i = 0; i < p_size2; i++) {
        free(pattern2[i]);
      }

      free(pattern2);
    }
  }
  return 0;
}
