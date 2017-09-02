#include <stdio.h>
#include "pin.H"

FILE * trace;

VOID Instruction(INS ins, VOID *v)
{
  fprintf(trace,"[%s]\n",(INS_Disassemble(ins)).c_str());
}

VOID Fini(INT32 code, VOID *v)
{
    fprintf(trace, "#eof\n");
    fclose(trace);
}

INT32 Usage()
{
    PIN_ERROR( "This Pintool logs instructions\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

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
