#include <stdio.h>
#include <unordered_map>
#include <set>
#include <iostream>
#include "pin.H"

FILE * trace;

static std::unordered_map<ADDRINT, std::string> str_of_img_at;
static std::set<std::pair<VOID*, ADDRINT>> memory_accesses;
static std::set<std::pair<ADDRINT, ADDRINT>> instructions;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
  "o", "branchlog.out", "specify output file name");

VOID RecordMemAcc(VOID* ip, VOID* addr, ADDRINT base)
{
  memory_accesses.insert(std::make_pair(addr, base));
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
  if(IMG_Valid(img))
      base = IMG_LowAddress(img);
  instructions.insert(std::make_pair(ins_addr, base));

  UINT32 memOperands = INS_MemoryOperandCount(ins);
  for (UINT32 memOp = 0; memOp < memOperands; memOp++)
  {
    INS_InsertPredicatedCall(
      ins, IPOINT_BEFORE, (AFUNPTR)RecordMemAcc,
      IARG_INST_PTR,
      IARG_MEMORYOP_EA, memOp,
      IARG_ADDRINT, base,
      IARG_END);
  }

}

VOID Fini(INT32 code, VOID *v)
{
  for(auto it : instructions)
  {
    std::string img = str_of_img_at[it.second];
    fprintf(trace, "0x%zx - %s\n", it.first - it.second, img.data());
  }
  for(auto it : memory_accesses)
  {
    std::string img = str_of_img_at[it.second];
    fprintf(trace, "0x%zx - %s\n", (size_t)it.first - (size_t)it.second, img.data());
  }
  fclose(trace);
}

INT32 Usage()
{
  PIN_ERROR( "This Pintool logs instructions and its memory accesses\n"
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
