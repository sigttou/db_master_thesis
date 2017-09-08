#include <stdio.h>
#include <unordered_map>
#include "pin.H"

FILE * trace;
ADDRINT cur_branch;
ADDRINT branch_target;
bool was_branch;

static std::unordered_map<ADDRINT, std::string> str_of_ins_at;
static std::unordered_map<ADDRINT, std::string> str_of_img_at;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
  "o", "branchlog.out", "specify output file name");

VOID printbranch(ADDRINT addr, ADDRINT target)
{
  std::string ins_str = str_of_ins_at[addr];
  // fprintf(trace, "[%s] - branching at %zx - target: %zx\n", ins_str.c_str(), addr, target);
  cur_branch = addr;
  branch_target = target;
  was_branch = true;
}

VOID printins(ADDRINT addr, ADDRINT base)
{
  if(was_branch)
  {
    std::string ins_str = str_of_ins_at[cur_branch];
    std::string img_str = str_of_img_at[base];
    fprintf(trace, "%zx - [%s] in %s ", cur_branch-base, ins_str.c_str(), img_str.c_str());
    if(branch_target == addr)
      fprintf(trace, "T\n");
    else
      fprintf(trace, "N\n");
  }
  was_branch = false;
}

VOID ImageLoad(IMG img, VOID *v)
{
  str_of_img_at[IMG_LowAddress(img)] = IMG_Name(img);
}

VOID Instruction(INS ins, VOID *v)
{
  ADDRINT ins_addr = INS_Address(ins);
  IMG img = IMG_FindByAddress(ins_addr);
  ADDRINT base = 0x0;
  string lib;
  if(IMG_Valid(img))
      base = IMG_LowAddress(img);

  str_of_ins_at[INS_Address(ins)] = INS_Disassemble(ins);
  if(INS_IsBranch(ins))
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printbranch, IARG_ADDRINT, INS_Address(ins), IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);
  else
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printins, IARG_ADDRINT, INS_Address(ins), IARG_ADDRINT, base, IARG_END);
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
  IMG_AddInstrumentFunction(ImageLoad, 0);
  INS_AddInstrumentFunction(Instruction, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}
