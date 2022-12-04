/* ===================================================================== */
// List of commands sent to victim from CNC server for testing:
//   shell,
//   list {/p, /s, /d},
//   kill /p 3040, kill /s AudioEndpointBuilder,
//   getf test.out 1 2 google.com,
//   putf test2 1 2 google.com,
//   start /p ..., start /s ..., whoami, v, pidrun ...,
//   geturl google.com test4.out,
//   quit
/* ===================================================================== */

#include <iostream>
#include <fstream>
#include <set>
#include "pin.H"

using namespace std;

set<pair<ADDRINT, ADDRINT>> edge_list; // store both vertices of edge in a pair
ofstream OutFile; // output file
ADDRINT next_source = 0; // globally tracked source 'vertex'/instruction address -- updated everytime this source's destination is reached
int counter = 0;

// This function is called before every instruction is executed
VOID inst_by_inst(ADDRINT inst) {
    if (0 == counter) {
        OutFile << "digraph controlflow {\r\n";
        counter++;
    }
    for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
        if (IMG_IsMainExecutable(img) && inst >= 4204925) { 
            if (next_source != 0 && inst != 0) {
                int s = edge_list.size();
                edge_list.insert(make_pair<ADDRINT, ADDRINT>(next_source, inst));
                if (edge_list.size() != s) {
                    OutFile << "\"0x" << hex << next_source << "\" -> " << "\"0x" << hex << inst << "\";\r\n";
                }
                break;
            }
        }
    }
    next_source = inst;
}

// This function is called in FINI() and simply writes the vector of edges to a .DOT file.
INT write_to_file(set<pair<ADDRINT, ADDRINT>> fin_vec) {
    OutFile << "digraph controlflow {" << endl;
    for (auto pair : fin_vec) {
        // ADDRINT (as name suggests) is an int representation of address, so need to stream it as a hex out to file
        OutFile << "\"0x" << hex << pair.first << "\" -> " << "\"0x" << hex << pair.second << "\";" << endl;
    }
    OutFile << "}" << endl;
    return 0;
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID* v) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)inst_by_inst, IARG_END);
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "cfg.dot", "specify output file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID* v) {
    // Write to a file since cout and cerr maybe closed by the application
    auto res = write_to_file(edge_list);
    if (0 == res || OutFile.is_open()) {
        OutFile.close();
    }
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage() {
    cerr << "This tool generates a dot file containing the dynamically run executable's CFG." << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char* argv[]) {
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Open file for output before all function calls.
    OutFile.open(KnobOutputFile.Value().c_str());

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
