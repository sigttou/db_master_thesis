#include <stdio.h>
#include <unordered_map>
#include "pin.H"

FILE * trace;
static std::unordered_map<ADDRINT, std::string> str_of_ins_at;

VOID printins(ADDRINT addr)
{
  std::string ins_str = str_of_ins_at[addr];
  fprintf(trace, "[%s]\n", ins_str.c_str());
}

VOID Instruction(INS ins, VOID *v)
{
  if(INS_IsBranchOrCall(ins))
  {
    str_of_ins_at[INS_Address(ins)] = INS_Disassemble(ins);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printins, IARG_ADDRINT, INS_Address(ins), IARG_END);
  }
}

VOID Fini(INT32 code, VOID *v)
{
  fclose(trace);
}

INT32 Usage()
{
  PIN_ERROR( "This Pintool logs instructions\n" 
            + KNOB_BASE::StringKnobSummary() + "\n");
  return -1;
}

int main(int argc, char *argv[])
{
  if (PIN_Init(argc, argv)) 
    return Usage();
  trace = fopen("inslog.out", "w");
  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}
