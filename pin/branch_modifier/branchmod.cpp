#include <stdio.h>
#include <unistd.h>
#include <unordered_map>
#include "pin.H"

FILE * trace;
ADDRINT cur_branch;
ADDRINT branch_target;
bool was_branch;
ADDRINT addr_to_check;
bool set;

static std::unordered_map<ADDRINT, std::string> str_of_ins_at;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
  "o", "branchmod.out", "specify output file name");

KNOB<string> KnobBranchAddr(KNOB_MODE_WRITEONCE, "pintool",
  "a", "0x0", "specify branch to change");
  
VOID printbranch(ADDRINT addr, ADDRINT base, ADDRINT target)
{
  addr = addr - base;
  std::string ins_str = str_of_ins_at[addr];
  fprintf(trace, "[%s] - branching at %zx - target: %zx\n", ins_str.c_str(), addr, target);
  cur_branch = addr;
  branch_target = target;
  was_branch = true;
  set = false;
}

VOID printins(ADDRINT addr, ADDRINT base, CONTEXT* ctxt)
{
  ADDRINT check_addr = addr;
  addr = addr-base;
  std::string ins_str = str_of_ins_at[addr];
  if(was_branch)
  {
    if(branch_target == check_addr)
    {
      fprintf(trace, "branch %zx taken [%s] (%zx)\n", cur_branch, ins_str.c_str(), addr);
      if(!set)
      {
        PIN_SetContextReg(ctxt, REG_INST_PTR, branch_target);
        fprintf(trace, "set to %zx\n", branch_target);
        set = true;
      }
    }
    else
    {
      fprintf(trace, "branch %zx NOT taken [%s] (%zx)\n", cur_branch, ins_str.c_str(), addr);
    }
    PIN_ExecuteAt(ctxt);
  }
  else
  {
      fprintf(trace, "[%s] (%zx)\n", ins_str.c_str(), addr);
  }
  was_branch = false;
}

VOID Instruction(INS ins, VOID *v)
{
  ADDRINT ins_addr = INS_Address(ins);
  IMG img = IMG_FindByAddress(ins_addr);
  ADDRINT base = 0x0;
  if(IMG_Valid(img))
      base = IMG_LowAddress(img);
  str_of_ins_at[ins_addr - base] = INS_Disassemble(ins);

  if(INS_IsBranch(ins))
  {
    if((ins_addr - base) == addr_to_check)
    {
      printf("%s %zx\n", IMG_Name(img).c_str(), base);
      // INS_InsertDirectJump(ins, IPOINT_AFTER, 0x7fffe435d46a);
      INS_Delete(ins);
    }
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printbranch, IARG_ADDRINT, INS_Address(ins), IARG_ADDRINT, base, IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
  }
  else
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printins, IARG_ADDRINT, INS_Address(ins), IARG_ADDRINT, base, IARG_CONTEXT, IARG_END);
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
  trace = fopen(KnobOutputFile.Value().c_str(), "w");
  sscanf(KnobBranchAddr.Value().c_str(), "%zx", &addr_to_check); 
  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}
