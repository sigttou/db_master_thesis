#include <stdio.h>
#include <unordered_map>
#include "pin.H"

FILE * trace;

VOID printbbl(ADDRINT addr)
{
  fprintf(trace, "0x%lx\n", addr);
}

VOID Trace(TRACE trace, VOID *v)
{
  for(BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
  {
    BBL_InsertCall(bbl, IPOINT_ANYWHERE, (AFUNPTR)printbbl,
      IARG_ADDRINT, BBL_Address(bbl), IARG_END);
  }
}

VOID Fini(INT32 code, VOID *v)
{
  fclose(trace);
}

INT32 Usage()
{
  PIN_ERROR( "This Pintool logs basic blocks\n" 
            + KNOB_BASE::StringKnobSummary() + "\n");
  return -1;
}

int main(int argc, char *argv[])
{
  if (PIN_Init(argc, argv)) 
    return Usage();
  trace = fopen("bbllog.out", "w");
  TRACE_AddInstrumentFunction(Trace, 0);
  PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}
