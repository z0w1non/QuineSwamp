#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <stdarg.h>

#define CONST const
#define VOID void

typedef unsigned char BYTE, * PBYTE;
typedef unsigned char BOOL;
typedef unsigned int UINT, * PUINT;
typedef int INT, * PINT;
typedef char CHAR, * PCHAR, * STRING;
typedef CONST CHAR * CSTRING;
typedef VOID * PVOID;
typedef size_t SIZE_T;

#define TRUE  1
#define FALSE 0
#define MAX_PATH 260
#define MAX_LABEL 260
#define MAX_NAME 260
#define MAX_MNEMONIC 32

#define TO_STRING_(s) #s
#define TO_STRING(s) TO_STRING_(s)

#ifdef NDEBUG
    #define DEBUG(...)
#else
    #define DEBUG_(file, func, line, ...) DebugImpl(file, func, line, __VA_ARGS__)
    #define DEBUG(...) DEBUG_(__FILE__, __func__, __LINE__, __VA_ARGS__)
#endif

#define OFFSET_(ptr, op, offset) ((VOID *)((CHAR *)ptr op offset))
#define OFFSET(ptr, op, offset) OFFSET_(ptr, op, offset)

#define DEFAULT_ASSEMBLY_SIZE 1024

#define IMPL(mnemonic) mnemonic ## _IMPL

enum
{
    SYSTEM = 0,
    USER   = 1
};

enum INSTRUCTION
{
    NOP    ,
    SEEK   ,
    ADD    ,
    SUB    ,
    AND    ,
    OR     ,
    XOR    ,
    NOT    ,
    SLA    ,
    SRA    ,
    SLL    ,
    SRL    ,
    READ   ,
    WRITE  ,
    SAVE   ,
    SWAP   ,
    SET    ,
    JMP    ,
    JEZ    ,
    PUSH   ,
    POP    ,
    CALL   ,
    RET    ,
    RSV    ,
    CPY    ,
    ADDR   ,
    SIZE   ,
    INSTRUCTION_NUMBER
};

#define FORWARD_DECLARATION(type) struct type##_; typedef type##_ type, * P##type
    FORWARD_DECLARATION(MEMORY          );
    FORWARD_DECLARATION(PROCESSOR       );
    FORWARD_DECLARATION(PROCESSOR_TABLE);
    FORWARD_DECLARATION(OWNER           );
    FORWARD_DECLARATION(OWNER_TABLE     );
    FORWARD_DECLARATION(WORLD           );
    FORWARD_DECLARATION(WORLD_PARAM     );
    FORWARD_DECLARATION(INSTRUCTION_INFO);
    FORWARD_DECLARATION(ASSEMBLY        );
    FORWARD_DECLARATION(SCORE_WONER_PAIR);
    FORWARD_DECLARATION(STRING_UINT_PAIR);
    FORWARD_DECLARATION(STRING_UINT_MAP );
#undef FORWARD_DECLARATION

typedef struct MEMORY_
{
    UINT    size;
    PBYTE   data;
    PBYTE   owner;
} MEMORY, * PMEMORY;

typedef struct PROCESSOR_
{
    UINT    pid;
    UINT    addr;
    UINT    size;
    UINT    pc;
    UINT    sp;
    UINT    ptr;
    UINT    acc;
    UINT    tmp;
    UINT    rsvcnt;
    UINT    rsvmax;
    PBYTE   rsvptr;
    UINT    step;
    BYTE    owner;
    CHAR    name[MAX_NAME];
} PROCESSOR, * PPROCESSOR;

typedef struct PROCESSOR_TABLE_
{
    UINT        size;
    PPROCESSOR  data;
    UINT        used;
} PROCESSOR_TABLE, * PPROCESSOR_TABLE;

typedef struct OWNER_
{
    CHAR name[MAX_PATH];
} OWNER, * POWNER;

typedef struct OWNER_TABLE_
{
    UINT   number;
    UINT   size;
    POWNER data;
} OWNER_TABLE, * POWNER_TABLE;

typedef struct WORLD_
{
    PMEMORY             mem;
    PPROCESSOR_TABLE    prcst;
    UINT                tick_number;
    POWNER_TABLE        owntbl;
} WORLD, * PWORLD;

typedef struct WORLD_PARAM_
{
    UINT memory_size;
    UINT processor_number;
    UINT tick_number;
} WORLD_PARAM, * PWORLD_PARAM;

typedef BOOL(*INSTRUCTION_IMPL)(PWORLD wld, PPROCESSOR prcs);

typedef struct INSTRUCTION_INFO_
{
    CHAR             mnemonic[MAX_MNEMONIC];
    BYTE             code;
    INSTRUCTION_IMPL impl;
} INSTRUCTION_INFO, * PINSTRUCTION_INFO;

typedef struct ASSEMBLY_
{
    UINT  size, maxsize;
    PBYTE data;
} ASSEMBLY, * PASSEMBLY;

typedef struct SCORE_WONER_PAIR_
{
    UINT score;
    UINT owner;
} SCORE_OWNER_PAIR, * PSCORE_OWNER_PAIR;

typedef struct STRING_UINT_PAIR_
{
    CHAR    label[MAX_LABEL];
    UINT    addr;
} STRING_UINT_PAIR, * PSTRING_UINT_PAIR;

typedef struct STRING_UINT_MAP_
{
    UINT size;
    UINT maxsize;
    PSTRING_UINT_PAIR data;
} STRING_UINT_MAP, * PSTRING_UINT_MAP;

typedef struct OPTIONS_
{
    BOOL options[52];
} OPTIONS, * POPTIONS;

VOID * NativeMalloc(SIZE_T size);
VOID * NativeRealloc(VOID * ptr, SIZE_T size);
VOID NativeFree(VOID * ptr);

UINT Random();
BYTE RandomInstruction();
UINT CreatePID();

PPROCESSOR_TABLE ProcessorTable_Create(UINT size);
VOID ProcessorTable_Release(PPROCESSOR_TABLE prcst);
BOOL ProcessorTable_Tick(PPROCESSOR_TABLE prcst, PWORLD wld);
PPROCESSOR ProcesserQueue_FindFreeProcessor(PMEMORY mem, PPROCESSOR_TABLE prcst);
PPROCESSOR ProcesserQueue_ReleaseOldest(PMEMORY mem, PPROCESSOR_TABLE prcst);
BOOL InitMemoryAndProcesserPrimary(PWORLD wld, BYTE owner, PBYTE data, UINT size);
BOOL InitMemoryAndProcesserSecondary(PWORLD wld, PPROCESSOR parent);

VOID Processor_RoundProgramCounter(PPROCESSOR prcs);
VOID Processor_IncreceProgramCounter(PPROCESSOR prcs, UINT cnt);
VOID Processor_DecreceProgramCounter(PPROCESSOR prcs);
BOOL Processor_Step(PPROCESSOR prcs, PWORLD wld);
VOID Processor_SetName(PPROCESSOR prcs, POWNER_TABLE owntbl);
VOID Processor_Dump(PPROCESSOR prcs);

PBYTE Memory_Data(PMEMORY mem, UINT addr);
PBYTE Memory_Owner(PMEMORY mem, UINT addr);

BOOL FindFreeMemoryAndProcessor(PMEMORY mem, PPROCESSOR_TABLE prcst, UINT size, PUINT addr, PPROCESSOR * prcs);

PMEMORY Memory_Create(UINT size);
VOID Memory_Release(PMEMORY mem);

POWNER_TABLE OwnerTable_Create(UINT size);
VOID OwnerTable_Release(POWNER_TABLE owntbl);
CSTRING OwnerTable_GetName(POWNER_TABLE owntbl, UINT owner);
BOOL OwnerTable_AddName(POWNER_TABLE owntbl, CSTRING name);

PWORLD World_Create(PWORLD_PARAM param);
VOID World_Release(PWORLD wld);
VOID World_JudgeResult(PWORLD wld);
BOOL World_Run(PWORLD wld);

BOOL Memory_Write(PMEMORY mem, PPROCESSOR prcs, UINT localaddr, BYTE data);
BYTE Memory_Read(PMEMORY mem, PPROCESSOR prcs, UINT localaddr, PBYTE data);
BOOL Memory_OutOfMemory(PMEMORY mem, UINT addr);

CSTRING CodeToMnemonic(BYTE code);
UINT MnemonicToCode(CSTRING mnemonic);
INSTRUCTION_IMPL CodeToImpl(BYTE code);
BOOL StringToUint(CSTRING s, PUINT value);
BOOL IsLabel(CSTRING s);

UINT ReadUInt(PBYTE destination);
VOID WriteUInt(PBYTE destination, UINT value);
BOOL ReplaceExtension(CSTRING source, PCHAR replaced, CSTRING extension);
BOOL GetBaseName(CSTRING source, PCHAR destination);
BOOL GetAssemblyFilePath(CSTRING source, PCHAR destination);
BOOL GetLogFilePath(CSTRING source, PCHAR destination);

PCHAR Tokens_CreateFromFile(CSTRING file);
VOID Tokens_Release(PCHAR tokens);

BOOL Assembly_Reserve(PASSEMBLY asm_, UINT size);
PASSEMBLY Assembly_AssembleFromFile(CSTRING file);
PASSEMBLY Assembly_ReadAssembledFile(CSTRING file);
VOID Assembly_Release(PASSEMBLY asm_);
BOOL Assembly_CreateFile(PASSEMBLY asm_, CSTRING path);

INT ScoreOwnerPairComparator(CONST VOID * a, CONST VOID * b);
CSTRING SuffixString(UINT n);

PSTRING_UINT_MAP StringUIntMap_Create();
VOID StringUIntMap_Release(PSTRING_UINT_MAP suimap);
BOOL StringUIntMap_Add(PSTRING_UINT_MAP suimap, CSTRING s, UINT ui);
BOOL StringUIntMap_Find(PSTRING_UINT_MAP suimap, CSTRING s, PUINT ui);

BOOL debug;
VOID Debug(CSTRING format, ...);
VOID DebugImpl(CSTRING file, CSTRING func, UINT line, CSTRING format, ...);

VOID DumpMemory(PMEMORY mem, UINT addr, UINT size);
VOID PrintHelp();

BOOL Options_EnabledOption(POPTIONS options, CHAR option);
VOID Options_ParseCommandLine(POPTIONS options, INT argc, CSTRING * argv);
BOOL IsNumber(CSTRING s);
BOOL ParseCommandLineParameter(INT argc, CSTRING * argv, CHAR c, PUINT param);
VOID ParseCommandLine(INT argc, CSTRING * argv);

VOID * NativeMalloc(SIZE_T size)
{
    if (!size)
        return NULL;
    VOID * tmp;
    tmp = malloc(size + sizeof(SIZE_T));
    if (!tmp)
        return NULL;
    *(SIZE_T *)tmp = size;
    memset(OFFSET(tmp, +, sizeof(SIZE_T)), 0, size);
    return OFFSET(tmp, +, sizeof(SIZE_T));
}

VOID * NativeRealloc(VOID * ptr, SIZE_T size)
{
    SIZE_T oldsize;
    VOID * bodyptr;
    if (!ptr || !size)
        return NULL;
    oldsize = *(SIZE_T *)OFFSET(ptr, -, sizeof(SIZE_T));
    if (size <= oldsize)
        return ptr;
    VOID * tmp = realloc(OFFSET(ptr, -, sizeof(SIZE_T)), size + sizeof(SIZE_T));
    if (!tmp)
        return NULL;
    *(SIZE_T *)tmp = size;
    bodyptr = OFFSET(tmp, +, sizeof(SIZE_T));
    memset(OFFSET(bodyptr, +, oldsize), 0, size - oldsize);
    return bodyptr;
}

VOID NativeFree(VOID * ptr)
{
    if (!ptr)
        return;
    free(OFFSET(ptr, -, sizeof(SIZE_T)));
}

UINT Random()
{
    static UINT X = 0;
    X = (X * 1664525 + 1013904223) & 2147483647;
    return X >> 16;
}

BYTE RandomInstruction()
{
    return Random() % INSTRUCTION_NUMBER;
}

UINT CreatePID()
{
    static UINT i = 0;
    return i++;
}

PPROCESSOR_TABLE ProcessorTable_Create(UINT size)
{
    PPROCESSOR_TABLE prcst = (PPROCESSOR_TABLE)NativeMalloc(sizeof(PROCESSOR_TABLE));
    if (!prcst)
        goto error;

    prcst->size = size;
    prcst->data = (PPROCESSOR)NativeMalloc(size * sizeof(PROCESSOR));
    if (!prcst->data)
        goto error;

    return prcst;

error:
    ProcessorTable_Release(prcst);
    return NULL;
}

VOID ProcessorTable_Release(PPROCESSOR_TABLE prcst)
{
    UINT i;
    if (prcst)
    {
        for (i = 0; i < prcst->size; ++i)
            NativeFree(prcst->data[i].rsvptr);
        NativeFree(prcst->data);
        NativeFree(prcst);
    }
}

BOOL ProcessorTable_Tick(PPROCESSOR_TABLE prcst, PWORLD wld)
{
    UINT i;
    for (i = 0; i < prcst->size; ++i)
        if (prcst->data[i].owner != SYSTEM)
            if (!Processor_Step(&prcst->data[i], wld))
                return FALSE;
    return TRUE;
}

PPROCESSOR ProcesserQueue_FindFreeProcessor(PMEMORY mem, PPROCESSOR_TABLE prcst)
{
    UINT i;
    for (i = 0; i < prcst->size; ++i)
        if (prcst->data[i].owner == SYSTEM)
            return &prcst->data[i];
    return NULL;
}

PPROCESSOR ProcesserQueue_ReleaseOldest(PMEMORY mem, PPROCESSOR_TABLE prcst)
{
    UINT i, maxused, maxoffset;
    PPROCESSOR oldest;

    maxused = 0;
    maxoffset = 0;
    for (i = 0; i < prcst->size; ++i)
    {
        if (prcst->data[i].step > maxused)
        {
            maxused = prcst->data[i].step;
            maxoffset = i;
        }
    }

    oldest = &prcst->data[maxoffset];
    Debug("oldest processer 0x%02X\n", maxoffset);

    for (i = 0; i < oldest->size; ++i)
        *Memory_Owner(mem, oldest->addr + i) = SYSTEM;

    return oldest;
}

BOOL InitMemoryAndProcesserPrimary(PWORLD wld, BYTE owner, PBYTE data, UINT size)
{
#define DEFAULT_RESERVE_MAX 1024

    UINT i, addr;
    PPROCESSOR prcs;

    if (!FindFreeMemoryAndProcessor(wld->mem, wld->prcst, size, &addr, &prcs))
        return FALSE;

    prcs->pid = CreatePID();
    prcs->addr = addr;
    prcs->size = size;
    prcs->pc = 0;
    prcs->sp = size;
    prcs->ptr = 0;
    prcs->acc = 0;
    prcs->tmp = 0;
    prcs->rsvcnt = 0;
    prcs->rsvmax = DEFAULT_RESERVE_MAX;
    prcs->rsvptr = (PBYTE)NativeMalloc(sizeof(BYTE) * prcs->rsvmax);
    if (!prcs->rsvptr)
        return FALSE;
    prcs->step = 0;
    prcs->owner = owner;
    Processor_SetName(prcs, wld->owntbl);

    for (i = 0; i < prcs->size; ++i)
    {
        *Memory_Data(wld->mem, addr + i) = data[i];
        *Memory_Owner(wld->mem, addr + i) = owner;
    }

    return TRUE;

#undef DEFAULT_RESERVE_MAX
}

BOOL InitMemoryAndProcesserSecondary(PWORLD wld, PPROCESSOR parent)
{
#define DEFAULT_RESERVE_MAX 1024

    UINT i, addr;
    PPROCESSOR prcs;

    if (!FindFreeMemoryAndProcessor(wld->mem, wld->prcst, parent->rsvcnt, &addr, &prcs))
        return FALSE;

    prcs->pid = CreatePID();
    prcs->addr = addr;
    prcs->size = parent->rsvcnt;
    prcs->pc = 0;
    prcs->sp = parent->rsvcnt;
    prcs->ptr = 0;
    prcs->acc = 0;
    prcs->tmp = 0;
    prcs->rsvcnt = 0;
    prcs->rsvmax = DEFAULT_RESERVE_MAX;
    prcs->rsvptr = (PBYTE)NativeMalloc(sizeof(BYTE) * prcs->rsvmax);
    if (!prcs->rsvptr)
        return FALSE;
    prcs->step = 0;
    prcs->owner = parent->owner;
    Processor_SetName(prcs, wld->owntbl);

    for (i = 0; i < prcs->size; ++i)
    {
        *Memory_Data(wld->mem, addr + i) = parent->rsvptr[i];
        *Memory_Owner(wld->mem, addr + i) = parent->owner;
        Debug("[0x%08X] <- 0x%02X\n", addr + i, *Memory_Data(wld->mem, addr + i));
    }

    return TRUE;

#undef DEFAULT_RESERVE_MAX
}

VOID Processor_RoundProgramCounter(PPROCESSOR prcs)
{
    if (prcs->pc >= prcs->size)
        prcs->pc = 0;
}

VOID Processor_IncreceProgramCounter(PPROCESSOR prcs, UINT cnt)
{
    prcs->pc += cnt;
    Processor_RoundProgramCounter(prcs);
}

VOID Processor_DecreceProgramCounter(PPROCESSOR prcs)
{
    if (prcs->pc == 0)
        prcs->pc = 0;
    else
        --prcs->pc;
}

BOOL Processor_Step(PPROCESSOR prcs, PWORLD wld)
{
    BYTE code;
    code = *Memory_Data(wld->mem, prcs->addr + prcs->pc);
    if (code < INSTRUCTION_NUMBER)
    {
        Debug("%s: [0x%02X] 0x%02X %s\n", prcs->name, prcs->pc, code, CodeToMnemonic(code));
        if (!CodeToImpl(code)(wld, prcs))
            return FALSE;
    }
    ++prcs->step;
    return TRUE;
}

VOID Processor_SetName(PPROCESSOR prcs, POWNER_TABLE owntbl)
{
    sprintf(prcs->name, "%s%d", OwnerTable_GetName(owntbl, prcs->owner), prcs->pid);
}

VOID Processor_Dump(PPROCESSOR prcs)
{
    printf("NAME  : 0x%s\n",   prcs->name  );
    printf("PC    : 0x%08X\n", prcs->pc    );
    printf("ACC   : 0x%08X\n", prcs->acc   );
    printf("TMP   : 0x%08X\n", prcs->tmp   );
    printf("PTR   : 0x%08X\n", prcs->ptr   );
    printf("SP    : 0x%08X\n", prcs->sp    );
    printf("ADDR  : 0x%08X\n", prcs->addr  );
    printf("SIZE  : 0x%08X\n", prcs->size  );
    printf("RSVCNT: 0x%08X\n", prcs->rsvcnt);
    printf("OWNER : 0x%08X\n", prcs->owner );
    printf("STEP  : 0x%08X\n", prcs->step  );
}

PBYTE Memory_Data(PMEMORY mem, UINT addr)
{
    return mem->data + addr;
}

PBYTE Memory_Owner(PMEMORY mem, UINT addr)
{
    return mem->owner + addr;
}

BOOL FindFreeMemoryAndProcessor(PMEMORY mem, PPROCESSOR_TABLE prcst, UINT size, PUINT addr, PPROCESSOR * prcs)
{
    UINT i, tmp;

    *addr = -1;
    *prcs = NULL;
    while (*addr == -1 || *prcs == NULL)
    {
        i = 0;
        while (!Memory_OutOfMemory(mem, i))
        {
            if (*Memory_Owner(mem, i) == SYSTEM)
            {
                tmp = 1;
                while (tmp < size && !Memory_OutOfMemory(mem, i + tmp) && *Memory_Owner(mem, i + tmp) == SYSTEM)
                    ++tmp;
                if (tmp == size)
                {
                    *addr = i;
                    Debug("Free memory found (addr=0x%08X size=0x%08X)\n", i, tmp);
                    goto free_memory_found;
                }
                i += tmp;
            }
            else
                ++i;
        }
    free_memory_found:
        *prcs = ProcesserQueue_FindFreeProcessor(mem, prcst);
        if (!*prcs)
            *prcs = ProcesserQueue_ReleaseOldest(mem, prcst);
    }

    return TRUE;
}

PMEMORY Memory_Create(UINT size)
{
    PMEMORY mem;

    mem = (PMEMORY)NativeMalloc(sizeof(MEMORY) * size);
    if (!mem)
        goto error;

    mem->size = size;
    
    mem->data = (PBYTE)NativeMalloc(sizeof(BYTE) * size);
    if (!mem->data)
        goto error;

    mem->owner = (PBYTE)NativeMalloc(sizeof(BYTE) * size);
    if (!mem->owner)
        goto error;

    return mem;

error:
    Memory_Release(mem);
    return NULL;
}

VOID Memory_Release(PMEMORY mem)
{
    if (mem)
    {
        NativeFree(mem->data);
        NativeFree(mem->owner);
        NativeFree(mem);
    }
}

POWNER_TABLE OwnerTable_Create(UINT size)
{
    POWNER_TABLE owntbl;
    
    owntbl = (POWNER_TABLE)NativeMalloc(sizeof(OWNER_TABLE));
    if (!owntbl)
        goto error;

    owntbl->size = size;
    owntbl->data = (POWNER)NativeMalloc(sizeof(OWNER));
    if (!owntbl->data)
        goto error;

    return owntbl;

error:
    OwnerTable_Release(owntbl);
    return NULL;
}

VOID OwnerTable_Release(POWNER_TABLE owntbl)
{
    if (owntbl)
    {
        NativeFree(owntbl->data);
        NativeFree(owntbl);
    }
}

CSTRING OwnerTable_GetName(POWNER_TABLE owntbl, UINT owner)
{
    return owntbl->data[owner - USER].name;
}

BOOL OwnerTable_AddName(POWNER_TABLE owntbl, CSTRING name)
{
    PCHAR c;
    if (owntbl->number >= owntbl->size)
        return FALSE;
    strcpy(owntbl->data[owntbl->number].name, name);
    for (c = owntbl->data[owntbl->number].name; *c; ++c)
        *c = toupper(*c);
    ++owntbl->number;
    return TRUE;
}

PWORLD World_Create(PWORLD_PARAM param)
{
    PWORLD wld;

    wld = (PWORLD)NativeMalloc(sizeof(WORLD));
    if (!wld)
        goto error;

    wld->mem = Memory_Create(param->memory_size);
    if (!wld->mem)
        goto error;

    wld->prcst = ProcessorTable_Create(param->processor_number);
    if (!wld->prcst)
        goto error;

    wld->tick_number = param->tick_number;

    wld->owntbl = OwnerTable_Create(UCHAR_MAX + 1);
    if (!wld->owntbl)
        goto error;

    return wld;

error:
    World_Release(wld);
    return NULL;
}

VOID World_Release(PWORLD wld)
{
    if (wld)
    {
        Memory_Release(wld->mem);
        ProcessorTable_Release(wld->prcst);
        OwnerTable_Release(wld->owntbl);
        NativeFree(wld);
    }
}

VOID World_JudgeResult(PWORLD wld)
{
    UINT i;
    PSCORE_OWNER_PAIR pairs;

    pairs = (PSCORE_OWNER_PAIR)NativeMalloc(wld->owntbl->size * sizeof(SCORE_OWNER_PAIR));

    for (i = 0; i < wld->owntbl->number; ++i)
        pairs[i].owner = i + USER;

    for (i = 0; i < wld->prcst->size; ++i)
        if (wld->prcst->data[i].owner != SYSTEM)
            pairs[wld->prcst->data[i].owner - USER].score += wld->prcst->data[i].size;

    qsort(pairs, wld->owntbl->number, sizeof(SCORE_OWNER_PAIR), ScoreOwnerPairComparator);

    for (i = 0; i < wld->owntbl->number; ++i)
        printf("%d%s %s (%d)\n", i + 1, SuffixString(i + 1), OwnerTable_GetName(wld->owntbl, pairs[i].owner), pairs[i].score);

    NativeFree(pairs);
}

BOOL World_Run(PWORLD wld)
{
    UINT i;
    for (i = 0; i < wld->tick_number; ++i)
        if (!ProcessorTable_Tick(wld->prcst, wld))
            return FALSE;
    return TRUE;
}

BOOL Memory_Write(PMEMORY mem, PPROCESSOR prcs, UINT localaddr, BYTE data)
{
    UINT globaladdr;
    globaladdr = prcs->addr + localaddr;
    if (globaladdr >= mem->size)
        return FALSE;
    if (prcs->owner != *Memory_Owner(mem, globaladdr))
        return FALSE;
    *Memory_Data(mem, globaladdr) = data;
    return TRUE;
}

BOOL Memory_Read(PMEMORY mem, PPROCESSOR prcs, UINT localaddr, PBYTE data)
{
    UINT globaladdr;
    globaladdr = prcs->addr + localaddr;
    if (globaladdr >= mem->size)
        return FALSE;
    *data = *Memory_Data(mem, globaladdr);
    return TRUE;
}

BOOL Memory_OutOfMemory(PMEMORY mem, UINT addr)
{
    return addr >= mem->size;
}

BOOL IMPL(NOP)(PWORLD wld, PPROCESSOR prcs)
{
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(SEEK)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->ptr = prcs->acc;
    Debug("PTR <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(ADD)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->acc += prcs->tmp;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(SUB)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->acc -= prcs->tmp;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(AND)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->acc &= prcs->tmp;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(OR)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->acc |= prcs->tmp;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(XOR)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->acc ^= prcs->tmp;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(NOT)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->acc = (prcs->acc != 0) ? 0 : ~0;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(SLA)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->acc = (prcs->tmp << prcs->acc) & ~1;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(SRA)(PWORLD wld, PPROCESSOR prcs)
{
    UINT msb;
    msb = prcs->acc & 0x80000000;
    prcs->acc = (prcs->tmp >> prcs->acc) | msb;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(SLL)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->acc = (prcs->tmp << prcs->acc) & 0x8FFFFFFF;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(SRL)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->acc = (prcs->tmp >> prcs->acc) & ~1;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(READ)(PWORLD wld, PPROCESSOR prcs)
{
    UINT i, value;
    BYTE data;

    value = 0;
    for (i = 0; i < sizeof(UINT); ++i)
    {
        if (!Memory_Read(wld->mem, prcs, prcs->ptr + i, &data))
        {
            prcs->pc = 0;
            return TRUE;
        }
        value |= data << (8 * i);
    }
    prcs->acc = value;
    Debug("ACC <- 0x%08X\n", prcs->acc);

    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(WRITE)(PWORLD wld, PPROCESSOR prcs)
{
    UINT i;
    BYTE data;

    for (i = 0; i < sizeof(UINT); ++i)
    {
        data = (BYTE)(prcs->acc >> (8 * i));
        if (!Memory_Write(wld->mem, prcs, prcs->ptr + i, data))
        {
            prcs->pc = 0;
            return TRUE;
        }
        Debug("[0x%08X] <- 0x%02X\n", prcs->ptr + i, data);
    }

    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(SAVE)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->tmp = prcs->acc;
    Debug("TMP <- 0x%08X\n", prcs->tmp);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(SWAP)(PWORLD wld, PPROCESSOR prcs)
{
    UINT tmp;
    tmp = prcs->tmp;
    prcs->tmp = prcs->acc;
    prcs->acc = tmp;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Debug("TMP <- 0x%08X\n", prcs->tmp);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(SET)(PWORLD wld, PPROCESSOR prcs)
{
    UINT i, value;
    BYTE data;

    value = 0;
    for (i = 0; i < sizeof(UINT); ++i)
    {
        if (!Memory_Read(wld->mem, prcs, prcs->pc + 1 + i, &data))
        {
            prcs->pc = 0;
            return TRUE;
        }
        value |= data << (i * 8);
    }
    prcs->acc = value;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1 + sizeof(UINT));
    return TRUE;
}

BOOL IMPL(JMP)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->pc = prcs->acc;
    Debug("PC <- 0x%08X\n", prcs->pc);
    Processor_RoundProgramCounter(prcs);
    return TRUE;
}

BOOL IMPL(JEZ)(PWORLD wld, PPROCESSOR prcs)
{
    Debug("TMP == 0x%08X\n", prcs->tmp);
    if (prcs->tmp == 0)
        prcs->pc = prcs->acc;
    else
        ++prcs->pc;
    Processor_RoundProgramCounter(prcs);
    return TRUE;
}

BOOL IMPL(PUSH)(PWORLD wld, PPROCESSOR prcs)
{
    --prcs->sp;
    if (!Memory_Write(wld->mem, prcs, prcs->sp, prcs->acc))
    {
        prcs->pc = 0;
        return TRUE;
    }
    Debug("PC <- 0x%08X\n", prcs->pc);
    Debug("SP <- 0x%08X\n", prcs->sp);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(POP)(PWORLD wld, PPROCESSOR prcs)
{
    BYTE data;
    if (!Memory_Read(wld->mem, prcs, prcs->sp, &data))
    {
        prcs->pc = 0;
        return TRUE;
    }
    prcs->acc = data;
    ++prcs->sp;
    Debug("PC <- 0x%08X\n", prcs->pc);
    Debug("SP <- 0x%08X\n", prcs->sp);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(CALL)(PWORLD wld, PPROCESSOR prcs)
{
    BYTE data;
    if (prcs->pc + 1 >= prcs->size)
    {
        Processor_RoundProgramCounter(prcs);
        return TRUE;
    }
    --prcs->sp;
    if (!Memory_Write(wld->mem, prcs, prcs->sp, prcs->pc + 2))
    {
        prcs->pc = 0;
        return TRUE;
    }
    if (!Memory_Read(wld->mem, prcs, prcs->pc + 1, &data))
    {
        prcs->pc = 0;
        return TRUE;
    }
    prcs->pc = data;
    Debug("PC <- 0x%08X\n", prcs->pc);
    Debug("SP <- 0x%08X\n", prcs->sp);
    return TRUE;
}

BOOL IMPL(RET)(PWORLD wld, PPROCESSOR prcs)
{
    BYTE data;
    if (!Memory_Read(wld->mem, prcs, prcs->sp, &data))
    {
        prcs->pc = 0;
        return TRUE;
    }
    prcs->pc = data;
    ++prcs->sp;
    Debug("PC <- 0x%08X\n", prcs->pc);
    Debug("SP <- 0x%08X\n", prcs->sp);
    Processor_RoundProgramCounter(prcs);
    return TRUE;
}

BOOL IMPL(RSV)(PWORLD wld, PPROCESSOR prcs)
{
    BYTE data;
    if (prcs->rsvcnt >= prcs->rsvmax)
    {
        prcs->rsvmax *= 2;
        prcs->rsvptr = (PBYTE)NativeRealloc(prcs->rsvptr, sizeof(BYTE) * prcs->rsvmax);
        if (!prcs->rsvptr)
            return FALSE;
    }
    if (!Memory_Read(wld->mem, prcs, prcs->ptr, &data))
    {
        prcs->pc = 0;
        return TRUE;
    }
    prcs->rsvptr[prcs->rsvcnt] = data;
    Debug("RSV[0x%08X] <- 0x%02X %s\n", prcs->rsvcnt, prcs->rsvptr[prcs->rsvcnt], CodeToMnemonic(prcs->rsvptr[prcs->rsvcnt]));
    ++prcs->rsvcnt;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(CPY)(PWORLD wld, PPROCESSOR prcs)
{
    UINT i;
    if (prcs->rsvcnt)
    {
        for (i = 0; i < prcs->rsvcnt; ++i)
            Debug("RSV[0x%08X] == 0x%02X %s\n", i, prcs->rsvptr[i], CodeToMnemonic(prcs->rsvptr[i]));
        Debug("STEP == 0x%08X\n", prcs->step);
        InitMemoryAndProcesserSecondary(wld, prcs);
        prcs->rsvcnt = 0;
    }
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(ADDR)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->acc = prcs->addr;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL IMPL(SIZE)(PWORLD wld, PPROCESSOR prcs)
{
    prcs->acc = prcs->size;
    Debug("ACC <- 0x%08X\n", prcs->acc);
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

INSTRUCTION_INFO instruction_info_table[] = {
#define DECLARE_INSTRUCTION_INFO(s) {TO_STRING(s), s, IMPL(s)}
    DECLARE_INSTRUCTION_INFO(NOP    ),
    DECLARE_INSTRUCTION_INFO(SEEK   ),
    DECLARE_INSTRUCTION_INFO(ADD    ),
    DECLARE_INSTRUCTION_INFO(SUB    ),
    DECLARE_INSTRUCTION_INFO(AND    ),
    DECLARE_INSTRUCTION_INFO(OR     ),
    DECLARE_INSTRUCTION_INFO(XOR    ),
    DECLARE_INSTRUCTION_INFO(NOT    ),
    DECLARE_INSTRUCTION_INFO(SLA    ),
    DECLARE_INSTRUCTION_INFO(SRA    ),
    DECLARE_INSTRUCTION_INFO(SLL    ),
    DECLARE_INSTRUCTION_INFO(SRL    ),
    DECLARE_INSTRUCTION_INFO(READ   ),
    DECLARE_INSTRUCTION_INFO(WRITE  ),
    DECLARE_INSTRUCTION_INFO(SAVE   ),
    DECLARE_INSTRUCTION_INFO(SWAP   ),
    DECLARE_INSTRUCTION_INFO(SET    ),
    DECLARE_INSTRUCTION_INFO(JMP    ),
    DECLARE_INSTRUCTION_INFO(JEZ    ),
    DECLARE_INSTRUCTION_INFO(PUSH   ),
    DECLARE_INSTRUCTION_INFO(POP    ),
    DECLARE_INSTRUCTION_INFO(CALL   ),
    DECLARE_INSTRUCTION_INFO(RET    ),
    DECLARE_INSTRUCTION_INFO(RSV),
    DECLARE_INSTRUCTION_INFO(CPY ),
    DECLARE_INSTRUCTION_INFO(ADDR   ),
    DECLARE_INSTRUCTION_INFO(SIZE   ),
#undef DECLARE_INSTRUCTION_INFO
};

CSTRING CodeToMnemonic(BYTE code)
{
    return instruction_info_table[code].mnemonic;
}

UINT MnemonicToCode(CSTRING mnemonic)
{
    UINT i;
    for (i = 0; i < sizeof(instruction_info_table) / sizeof(*instruction_info_table); ++i)
        if (stricmp(mnemonic, instruction_info_table[i].mnemonic) == 0)
            return instruction_info_table[i].code;
    return -1;
}

INSTRUCTION_IMPL CodeToImpl(BYTE code)
{
    if (code >= INSTRUCTION_NUMBER)
        return instruction_info_table[NOP].impl;
    return instruction_info_table[code].impl;
}

BOOL StringToUint(CSTRING s, PUINT value)
{
    CSTRING cur;

    if (s == NULL || s[0] == '\0')
        return FALSE;

    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
    {
        for (cur = s + 2; *cur != '\0'; ++cur)
            if (!isxdigit(*cur))
                return FALSE;

        if (strlen(s) > 10)
            return FALSE;

        *value = 0;
        for (cur = s + 2; *cur != '\0'; ++cur)
        {
            *value *= 0x10;
            if (isdigit(*cur))
                *value += *cur - '0';
            else if (*cur >= 'a' && *cur <= 'f')
                *value += *cur - 'a' + 0xa;
            else if (*cur >= 'A' && *cur <= 'F')
                *value += *cur - 'A' + 0xa;
        }
        return TRUE;
    }
    else
    {
        for (cur = s; *cur != '\0'; ++cur)
            if (!isdigit(*cur))
                return FALSE;

        if (strlen(s) > 10)
            return FALSE;

        *value = 0;
        for (cur = s; *cur != '\0'; ++cur)
        {
            *value *= 10;
            *value += *cur - '0';
        }
        return TRUE;
    }
}

BOOL IsLabel(CSTRING s)
{
    UINT len, i;
    len = strlen(s);
    if (len == 0)
        return FALSE;
    if (!isalpha(s[0]) && s[0] != '_')
        return FALSE;
    if (MnemonicToCode(s) != -1)
        return FALSE;
    for (i = 1; i < len; ++i)
        if (!isalnum(s[i]) && s[i] != '_')
            return FALSE;
    return TRUE;
}

UINT ReadUInt(PBYTE destination)
{
    UINT i, value;
    value = 0;
    for (i = 0; i < sizeof(UINT); ++i)
        value |= destination[i] << (8 * (sizeof(UINT) - 1 - i));
    return value;
}

VOID WriteUInt(PBYTE destination, UINT value)
{
    UINT i;
    for (i = 0; i < sizeof(UINT); ++i)
        destination[i] = ((value >> (8 * i)) & 0xff);
}

BOOL ReplaceExtension(CSTRING source, PCHAR replaced, CSTRING extension)
{
    CSTRING name, ext;

    if (!source || !replaced)
        return FALSE;

    name = strrchr(source, '\\');
    ext = strrchr(source, '.');

    if ((!name && !ext) || (name && !ext) || (name && ext && ext < name))
    {
        strcpy(replaced, source);
        strcat(replaced, extension);
        return TRUE;
    }

    strcpy(replaced, source);
    replaced[ext - source] = '\0';
    strcat(replaced, extension);
    return TRUE;
}

BOOL GetBaseName(CSTRING source, PCHAR destination)
{
    return ReplaceExtension(source, destination, "");
}

BOOL GetAssemblyFilePath(CSTRING source, PCHAR destination)
{
    return ReplaceExtension(source, destination, ".qs");
}

BOOL GetLogFilePath(CSTRING source, PCHAR destination)
{
    return ReplaceExtension(source, destination, ".log");
}

BOOL Assembly_Reserve(PASSEMBLY asm_, UINT size)
{
    if (asm_->size + size <= asm_->maxsize)
        return TRUE;

    asm_->data = (PBYTE)NativeRealloc(asm_->data, asm_->maxsize * 2);
    asm_->maxsize *= 2;

    if (!asm_->data)
        return FALSE;

    return TRUE;
}

BOOL Tokens_Reserve(PCHAR * tokens, PUINT maxsize, UINT reserve)
{
    if (reserve < *maxsize)
        return TRUE;
    *maxsize *= 2;
    *tokens = (PCHAR)NativeRealloc(*tokens, *maxsize);
    if (!tokens)
        return FALSE;
    return TRUE;
}

PCHAR Tokens_CreateFromFile(CSTRING file)
{
#define MAX_TOKEN 1024

    FILE * fp;
    UINT token_size;
    INT c;
    CHAR token[MAX_TOKEN];
    PCHAR tokens;
    UINT tokens_size, tokens_maxsize;
    BOOL valid;

    valid = FALSE;
   
    fp = fopen(file, "rb");
    if (!fp)
        return NULL;

    tokens_size = 0;
    tokens_maxsize = MAX_TOKEN * 2;
    tokens = (PCHAR)NativeMalloc(sizeof(CHAR) * tokens_maxsize);
    if (!tokens)
        goto cleanup;

    token_size = 0;
    while ((c = fgetc(fp)) != EOF)
    {
        if (isalnum(c) || c == '_')
        {
            if (token_size + 1 == MAX_TOKEN)
            {
                token[MAX_TOKEN - 1] = '\0';
                fprintf(stderr, "token too long %s...\n", token);
                goto cleanup;
            }
            token[token_size++] = c;

        }
        else if (isspace(c) || c == ':')
        {
            if (token_size > 0)
            {
                token[token_size] = '\0';
                if (!Tokens_Reserve(&tokens, &tokens_maxsize, tokens_size + token_size + 1))
                    goto cleanup;
                strcpy(tokens + tokens_size, token);
                tokens_size += token_size + 1;
                token_size = 0;
            }

            if (c == ':')
            {
                if (!Tokens_Reserve(&tokens, &tokens_maxsize, tokens_size + 2))
                    goto cleanup;
                strcpy(tokens + tokens_size, ":");
                tokens_size += 2;
            }
        }
        else
        {
            fprintf(stderr, "invalid character %c\n", c);
            goto cleanup;
        }
    }

    if (token_size > 0)
    {
        token[token_size] = '\0';
        if (!Tokens_Reserve(&tokens, &tokens_maxsize, tokens_size + token_size + 1))
            goto cleanup;
        strcpy(tokens + tokens_size, token);
        tokens_size += token_size + 1;
        token_size = 0;
    }

    if (!Tokens_Reserve(&tokens, &tokens_maxsize, tokens_size + 1))
        goto cleanup;
    tokens[tokens_size] = '\0';

    valid = TRUE;

cleanup:
    fclose(fp);

    if (!valid)
    {
        Tokens_Release(tokens);
        return NULL;
    }

    return tokens;

#undef LINE_LENGTH_FORMAT
#undef LINE_LENGTH
}

VOID Tokens_Release(PCHAR tokens)
{
    NativeFree(tokens);
}

struct UINT_UINT_PAIR_;
typedef struct UINT_UINT_PAIR_
{
    UINT a, b;
} UINT_UINT_PAIR, * PUINT_UINT_PAIR;

PASSEMBLY Assembly_AssembleFromFile(CSTRING file)
{
#define LINE_LENGTH_FORMAT 1024
#define LINE_LENGTH (LINE_LENGTH_FORMAT + 1)

    PASSEMBLY asm_;
    UINT code;
    UINT value, i;
    BOOL valid;
    PSTRING_UINT_MAP label_to_address, pending_label;
    PCHAR tokens, token, next_token;

    valid = FALSE;
    asm_ = NULL;
    label_to_address = NULL;
    pending_label = NULL;
    tokens = NULL;
    next_token = NULL;

    asm_ = (PASSEMBLY)NativeMalloc(sizeof(ASSEMBLY));
    if (!asm_)
        goto cleanup;

    asm_->data = (PBYTE)NativeMalloc(sizeof(BYTE) * DEFAULT_ASSEMBLY_SIZE);
    asm_->maxsize = DEFAULT_ASSEMBLY_SIZE;
    if (!asm_->data)
        goto cleanup;

    label_to_address = StringUIntMap_Create();
    if (!label_to_address)
        goto cleanup;

    pending_label = StringUIntMap_Create();
    if (!pending_label)
        goto cleanup;

    tokens = Tokens_CreateFromFile(file);

    DEBUG("file=%s\n", file);
    DEBUG("tokens=%p\n", tokens);

    token = tokens;
    next_token = NULL;
    while (*token)
    {
        DEBUG("token=\"%s\"\n", token);
        next_token = token;
        while (*next_token)
            ++next_token;
        ++next_token;

        if (strcmp(next_token, ":") == 0 && IsLabel(token))
        {
            DEBUG("label \"%s\" 0x%08X\n", token, asm_->size);
            if (StringUIntMap_Find(label_to_address, token, NULL))
                fprintf(stderr, "already declared label \"%s\"\n", token);
            else if (!StringUIntMap_Add(label_to_address, token, asm_->size))
                goto cleanup;

            token = next_token + 2;
        }
        else if (StringUIntMap_Find(label_to_address, token, &value) || StringToUint(token, &value))
        {
            DEBUG("value 0x%08X\n", value);
            if (!Assembly_Reserve(asm_, asm_->size + sizeof(value)))
                goto cleanup;
            WriteUInt(&asm_->data[asm_->size], value);
            asm_->size += sizeof(value);

            token = next_token;
        }
        else if ((code = MnemonicToCode(token)) != -1)
        {
            DEBUG("instruction %s (0x%02x)\n", token, (BYTE)code);
            if (!Assembly_Reserve(asm_, asm_->size + sizeof(BYTE)))
                goto cleanup;
            asm_->data[asm_->size] = (BYTE)code;
            asm_->size += sizeof(BYTE);

            token = next_token;
        }
        else
        {
            DEBUG("pending lable \"%s\"\n", token);
            if (!StringUIntMap_Add(pending_label, token, asm_->size))
                goto cleanup;
            asm_->size += sizeof(UINT);

            token = next_token;
        }
    }

    for (i = 0; i < pending_label->size; ++i)
    {
        DEBUG("pending label \"%s\"\n", pending_label->data[i].label);

        if (!StringUIntMap_Find(label_to_address, pending_label->data[i].label, &value))
        {
            DEBUG("unresolved lable \"%s\"\n", pending_label->data[i].label);
            goto cleanup;
        }
        if (!Assembly_Reserve(asm_, asm_->size + sizeof(value)))
            goto cleanup; 
        WriteUInt(&asm_->data[pending_label->data[i].addr], value);
        DEBUG("pending label \"%s\" 0x%08X is resolved to 0x%08X\n", pending_label->data[i].label, pending_label->data[i].addr, value);
    }

    for (i = 0; i < label_to_address->size; ++i)
    {
        DEBUG("label \"%s\" 0x%08X\n", label_to_address->data[i].label, label_to_address->data[i].addr);
    }

    valid = TRUE;

cleanup:

    StringUIntMap_Release(label_to_address);
    StringUIntMap_Release(pending_label);
    Tokens_Release(tokens);

    if (!valid)
    {
        if (asm_)
        {
            NativeFree(asm_->data);
            NativeFree(asm_);
        }
        return NULL;
    }

    return asm_;

#undef LINE_LENGTH
#undef LINE_LENGTH_FORMAT
}

PASSEMBLY Assembly_ReadAssembledFile(CSTRING file)
{
    FILE * fp;
    PASSEMBLY asm_;
    INT c;
    BOOL valid;

    fp = fopen(file, "rb");

    if (!fp)
        return NULL;

    valid = FALSE;

    asm_ = (PASSEMBLY)NativeMalloc(sizeof(ASSEMBLY));
    if (!asm_)
        goto cleanup;

    asm_->data = (PBYTE)NativeMalloc(sizeof(BYTE) * DEFAULT_ASSEMBLY_SIZE);
    asm_->maxsize = DEFAULT_ASSEMBLY_SIZE;
    if (!asm_->data)
        goto cleanup;

    while ((c = fgetc(fp)) != EOF)
    {
        if (!Assembly_Reserve(asm_, asm_->size + 1))
            goto cleanup;
        asm_->data[asm_->size] = (BYTE)(UINT)c;
        ++asm_->size;
    }

    valid = TRUE;

cleanup:
    fclose(fp);

    if (!valid)
    {
        Assembly_Release(asm_);
        return NULL;
    }

    return asm_;
}


VOID Assembly_Release(PASSEMBLY asm_)
{
    if (asm_)
    {
        NativeFree(asm_->data);
        NativeFree(asm_);
    }
}

BOOL Assembly_CreateFile(PASSEMBLY asm_, CSTRING path)
{
    FILE * fp;
    BOOL result;

    result = FALSE;

    fp = fopen(path, "wb");
    if (!fp)
        return FALSE;

    if (fwrite(asm_->data, sizeof(BYTE), asm_->size, fp) == asm_->size)
        result = TRUE;

    fclose(fp);

    return result;
}

INT ScoreOwnerPairComparator(CONST VOID * a, CONST VOID * b)
{
    return ((PSCORE_OWNER_PAIR)b)->score - ((PSCORE_OWNER_PAIR)a)->score;
}

CSTRING SuffixString(UINT n)
{
    if (n == 1)
        return "st";
    if (n == 2)
        return "nd";
    if (n == 3)
        return "rd";
    return "th";
}

PSTRING_UINT_MAP StringUIntMap_Create()
{
#define STRING_UINT_MAP_DEFAULT_MAX_SIZE 256

    PSTRING_UINT_MAP suimap;

    suimap = (PSTRING_UINT_MAP)NativeMalloc(sizeof(STRING_UINT_MAP));
    if (!suimap)
        return NULL;
    
    suimap->maxsize = STRING_UINT_MAP_DEFAULT_MAX_SIZE;
    suimap->data = (PSTRING_UINT_PAIR)NativeMalloc(sizeof(STRING_UINT_PAIR) * suimap->maxsize);
    if (!suimap->data)
        goto error;

    return suimap;

error:
    StringUIntMap_Release(suimap);
    return NULL;

#undef STRING_UINT_MAP_DEFAULT_MAX_SIZE
}

VOID StringUIntMap_Release(PSTRING_UINT_MAP suimap)
{
    if (suimap)
    {
        NativeFree(suimap->data);
        NativeFree(suimap);
    }
}

BOOL StringUIntMap_Add(PSTRING_UINT_MAP suimap, CSTRING s, UINT ui)
{
    if (suimap->size >= suimap->maxsize)
    {
        suimap->maxsize *= 2;
        suimap->data = (PSTRING_UINT_PAIR)NativeRealloc(suimap->data, sizeof(STRING_UINT_PAIR) * suimap->maxsize);
        if (!suimap->data)
            return FALSE;
    }

    strcpy(suimap->data[suimap->size].label, s);
    suimap->data[suimap->size].addr = ui;
    ++suimap->size;
    return TRUE;
}

BOOL StringUIntMap_Find(PSTRING_UINT_MAP suimap, CSTRING s, PUINT ui)
{
    UINT i;

    for (i = 0; i < suimap->size; ++i)
    {
        if (stricmp(suimap->data[i].label, s) == 0)
        {
            if (ui)
                *ui = suimap->data[i].addr;
            return TRUE;
        }
    }

    return FALSE;
}

VOID Debug(CSTRING format, ...)
{
    if (!debug)
        return;
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

VOID DebugImpl(CSTRING file, CSTRING func, UINT line, CSTRING format, ...)
{
    va_list args;
    va_start(args, format);

    printf("%s(%d): ", func, line);
    vprintf(format, args);

    va_end(args);
}

VOID DumpMemory(PMEMORY mem, UINT addr, UINT size)
{
    UINT i;
    BYTE code;
    for (i = 0; i < size; ++i)
    {
        code = *Memory_Data(mem, addr + i);
        DEBUG("0x%08X 0x%02x (%s)", addr + i, code, CodeToMnemonic(code));
    }
}

VOID PrintHelp()
{
    printf("Alllowed options:\n");
    printf("    -h : produce help message\n");
    printf("    -d : debug assembly file\n");
}

BOOL Options_EnabledOption(POPTIONS options, CHAR option)
{
    if (option >= 'a' && option <= 'z')
        return options->options[option - 'a'];
    else if (option >= 'A' && option <= 'Z')
        return options->options[26 + option - 'A'];
    else
        return FALSE;
}

BOOL Options_ParseArgment(POPTIONS options, CSTRING arg)
{
    UINT i;
    CSTRING p;
    BOOL tempOptions[52];

    if (arg[0] != '-')
        return FALSE;

    if (options)
        memset(tempOptions, 0, 52);
    
    for (p = arg + 1; *p; ++p)
    {
        if (*p >= 'a' && *p <= 'z')
            tempOptions[*p - 'a'] = TRUE;
        else if (*p >= 'A' && *p <= 'Z')
            tempOptions[26 + *p - 'A'] = TRUE;
        else
            return FALSE;
    }
    
    if (options)
        for (i = 0; i < 52; ++i)
            options->options[i] |= tempOptions[i];

    return TRUE;
}

VOID Options_ParseCommandLine(POPTIONS options, INT argc, CSTRING * argv)
{
    UINT i;
    memset(options, 0, sizeof(*options));
    for (i = 0; i < (UINT)argc; ++i)
        Options_ParseArgment(options, argv[i]);
}

BOOL IsNumber(CSTRING s)
{
    CSTRING c;
    for (c = s; *c; ++c)
        if (!isdigit(*c))
            return FALSE;
    return TRUE;
}

BOOL ParseCommandLineParameter(INT argc, CSTRING * argv, CHAR c, PUINT param)
{
    UINT i, end;
    end = (UINT)argc - 1;
    for (i = 1; i < end; ++i)
        if (strlen(argv[i]) == 2 && argv[i][0] == '-' && argv[i][1] == c)
        {
            if (IsNumber(argv[i + 1]))
            {
                if (param)
                    *param = atoi(argv[i + 1]);
                return TRUE;
            }
            else
            {
                fprintf(stderr, "%c parameter is not a number (\"%s\")", c, argv[i + 1]);
                return FALSE;
            }
        }
    return FALSE;
}

VOID ParseCommandLine(INT argc, CSTRING * argv)
{
    UINT i;
    PASSEMBLY asm_;
    CHAR asmpath[MAX_PATH], basename[MAX_PATH];
    PWORLD wld;
    OPTIONS options;

    WORLD_PARAM param = {
        1000 * 10,      // memory_size
        32,             // processor_number
        5000            // tick_number
    };

    memset(asmpath, 0, sizeof(asmpath));

    Options_ParseCommandLine(&options, argc, argv);

    if (argc == 2 && !Options_ParseArgment(NULL, argv[1]))
    {
        PASSEMBLY asm_ = Assembly_AssembleFromFile(argv[1]);
        if (asm_)
        {
            memset(asmpath, 0, sizeof(asmpath));
            if (GetAssemblyFilePath(argv[1], asmpath))
            {
                if (Assembly_CreateFile(asm_, asmpath))
                    fprintf(stdout, "Assemble succseed\n");
                else
                    fprintf(stderr, "Assemble failed\n");
            }
        }
        return;
    }

    if (Options_EnabledOption(&options, 'h') || argc < 2)
    {
        PrintHelp();
        return;
    }

    if (Options_EnabledOption(&options, 'd'))
    {
        debug = TRUE;

        ParseCommandLineParameter(argc, argv, 'm', &param.memory_size     );
        ParseCommandLineParameter(argc, argv, 'p', &param.processor_number);
        ParseCommandLineParameter(argc, argv, 't', &param.tick_number     );
        printf("Memory size      = %d\n", param.memory_size     );
        printf("Processor number = %d\n", param.processor_number);
        printf("Tick number      = %d\n", param.tick_number     );

        wld = World_Create(&param);

        for (i = 1; i < (UINT)argc; ++i)
        {
            if (!Options_ParseArgment(NULL, argv[i]) && !IsNumber(argv[i]))
            {
                memset(basename, 0, sizeof(basename));
                GetBaseName(argv[i], basename);
                OwnerTable_AddName(wld->owntbl, basename);
                asm_ = Assembly_ReadAssembledFile(argv[i]);
                if (asm_)
                {
                    InitMemoryAndProcesserPrimary(wld, wld->owntbl->number, asm_->data, asm_->size);
                    Assembly_Release(asm_);
                }
            }
        }

        if (!World_Run(wld))
        {
            fprintf(stderr, "runtime error\n");
        }

        World_JudgeResult(wld);
        World_Release(wld);
    }
}

INT main(INT argc, CSTRING * argv)
{
    ParseCommandLine(argc, argv);
    return 0;
}
