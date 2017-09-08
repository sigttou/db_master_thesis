#include <stdio.h>
#include <unistd.h>
#include <unordered_map>
#include "pin.H"

FILE * trace;
ADDRINT cur_branch;
ADDRINT branch_target;
bool was_branch;

static std::unordered_map<ADDRINT, std::string> str_of_ins_at;

VOID printbranch(ADDRINT addr, ADDRINT target)
{
  std::string ins_str = str_of_ins_at[addr];
  fprintf(trace, "[%s] - branching at %zx - target: %zx\n", ins_str.c_str(), addr, target);
  cur_branch = addr;
  branch_target = target;
  was_branch = true;
}

VOID printins(ADDRINT addr)
{
  std::string ins_str = str_of_ins_at[addr];
  if(was_branch)
  {
    if(branch_target == addr)
      fprintf(trace, "branch %zx taken [%s] (%zx)\n", cur_branch, ins_str.c_str(), addr);
    else
      fprintf(trace, "branch %zx NOT taken [%s] (%zx)\n", cur_branch, ins_str.c_str(), addr);
  }
  else
  {
      fprintf(trace, "[%s] (%zx)\n", ins_str.c_str(), addr);
  }
  was_branch = false;
}

VOID Instruction(INS ins, VOID *v)
{
  str_of_ins_at[INS_Address(ins)] = INS_Disassemble(ins);
  if(INS_IsBranch(ins))
  {
    if(INS_Address(ins) == 0x7fffe435c6a1)
    {
      // INS_InsertDirectJump(ins, IPOINT_AFTER, 0x7fffe435d46a);
      INS_Delete(ins);
    }
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printbranch, IARG_ADDRINT, INS_Address(ins), IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
  }
  else
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printins, IARG_ADDRINT, INS_Address(ins), IARG_END);
}

VOID Fini(INT32 code, VOID *v)
{
  fclose(trace);
}

INT32 Usage()
{
  PIN_ERROR( "This Pintool logs instructions and its branch\n" 
            + KNOB_BASE::StringKnobSummary() + "\n");
  return -1;
}

int main(int argc, char *argv[])
{
  if (PIN_Init(argc, argv)) 
    return Usage();
  trace = fopen("branchmod.out", "w");
  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}
