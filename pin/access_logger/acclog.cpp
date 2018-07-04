#include <stdio.h>
#include <unordered_map>
#include <set>
#include <iostream>
#include "pin.H"

FILE * trace;

static std::unordered_map<ADDRINT, std::string> str_of_img_at;
static std::unordered_map<ADDRINT, ADDRINT> img_offsets;
static std::unordered_map<std::string, std::unordered_map<std::string, std::pair<ADDRINT, ADDRINT>>> section_areas;
static std::unordered_map<std::string, std::unordered_map<std::string, ADDRINT>> section_offsets;
static std::unordered_map<std::string, std::set<ADDRINT>> to_print;
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
  for(SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec))
  {
    if(SEC_Mapped(sec))
    {
      section_areas[IMG_Name(img)][SEC_Name(sec)] = std::make_pair(SEC_Address(sec) - IMG_LoadOffset(img), SEC_Address(sec) - IMG_LoadOffset(img) + SEC_Size(sec));
      section_offsets[IMG_Name(img)][SEC_Name(sec)] = (size_t)SEC_Data(sec) - IMG_StartAddress(img);
    }
  }
  str_of_img_at[IMG_LowAddress(img)] = IMG_Name(img);
}

VOID Instruction(INS ins, VOID *v)
{
  ADDRINT ins_addr = INS_Address(ins);
  IMG img = IMG_FindByAddress(ins_addr);
  ADDRINT base = 0x0;
  ADDRINT offset = 0x0;
  if(IMG_Valid(img))
  {
    base = IMG_LowAddress(img);
    offset = IMG_LoadOffset(img);
  }
  img_offsets[base] = offset;
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
    bool is_set = false;
    std::string img = str_of_img_at[it.second];
    ADDRINT offset = img_offsets[it.second];
    for(auto sec_it : section_areas[img])
    {
        if((size_t)it.first - offset >= sec_it.second.first && (size_t)it.first - offset <= sec_it.second.second)
        {
          to_print[img.data()].insert((size_t)it.first - (size_t)offset - sec_it.second.first + section_offsets[img][sec_it.first]);
          is_set = true;
          break;
        }
    }
    if(!is_set)
      to_print[img.data()].insert(it.first - offset);
  }
  for(auto it : memory_accesses)
  {
    bool is_set = false;
    std::string img = str_of_img_at[it.second];
    ADDRINT offset = img_offsets[it.second];
    for(auto sec_it : section_areas[img])
    {
        if((size_t)it.first - offset >= sec_it.second.first && (size_t)it.first - offset <= sec_it.second.second)
        {
          to_print[img.data()].insert((size_t)it.first - (size_t)offset - sec_it.second.first + section_offsets[img][sec_it.first]);
          is_set = true;
          break;
        }
    }
    if(!is_set)
      to_print[img.data()].insert((size_t)it.first - (size_t)offset);
  }

  for(auto it : to_print)
  {
    for(auto addr : it.second)
      fprintf(trace, "0x%zx - %s\n", addr, it.first.c_str());
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
