#pragma once

#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

using std::cout;
using std::endl;
using std::string;

class Output
{
public:
  Output();

  /// Stores the JSON structure in <data> locally
  template <typename T>
  static void storeJSON(const T& data)
  {
    string filename ="output.json";
    std::ofstream fileOutput(filename);
    if (!fileOutput) {
      cout << "Cannot create file: "  << filename << endl;
    }
    cout << "Saving the output in the file: "  << filename << endl;

    fileOutput << std::setw(2) << data << std::endl;
    fileOutput.close();
  }

private:

};