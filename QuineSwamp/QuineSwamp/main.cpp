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
typedef char CHAR, * PCHAR;
typedef CONST CHAR * PCONST_CHAR;
typedef VOID * PVOID;

#define TRUE  1
#define FALSE 0
#define MAX_PATH 260
#define MAX_LABEL 36

#define TO_STRING_(s) #s
#define TO_STRING(s) TO_STRING_(s)

#ifdef NDEBUG
    #define DEBUG(...)
#else
    #define DEBUG_(file, func, line, ...) Debug(file, func, line, __VA_ARGS__)
    #define DEBUG(...) DEBUG_(__FILE__, __func__, __LINE__, __VA_ARGS__)
#endif

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
    RESERVE,
    MALLOC ,
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
    FORWARD_DECLARATION(STRING          );
    FORWARD_DECLARATION(VECTOR          );
#undef FORWARD_DECLARATION

typedef CONST PSTRING PCONST_STRING;

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
    UINT    rgst;
    UINT    tmp;
    UINT    rsv;
    UINT    rsvmax;
    PBYTE   rsvptr;
    UINT    used;
    BYTE    owner;
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
    UINT   size;
    POWNER data;
} OWNER_TABLE, * POWNER_TABLE;

typedef struct WORLD_
{
    PMEMORY             mem;
    PPROCESSOR_TABLE    prcst;
    UINT                iteration_number;
    POWNER_TABLE        owntbl;
} WORLD, * PWORLD;

typedef struct WORLD_PARAM_
{
    UINT memory_size;
    UINT program_number;
    UINT iteration_number;
    UINT owner_number;
} WORLD_PARAM, * PWORLD_PARAM;

typedef BOOL(*INSTRUCTION_IMPL)(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs);

typedef struct INSTRUCTION_INFO_
{
    CHAR             mnemonic[32];
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

typedef struct STRING_
{
    UINT size;
    UINT maxsize;
    PCHAR data;
} STRING, * PSTRING;

typedef struct VECTOR_
{
    UINT size;
    UINT maxsize;
    PVOID data;
} VECTOR, * PVECTOR;

VOID * NativeMalloc(UINT size);
VOID * NativeRealloc(VOID * ptr, UINT size);
VOID NativeFree(VOID * ptr);

UINT Random();
BYTE RandomInstruction();
UINT CreatePID();

PPROCESSOR_TABLE ProcessorTable_Create(UINT size);
VOID ProcessorTable_Release(PPROCESSOR_TABLE prcst);
BOOL ProcessorTable_Tick(PPROCESSOR_TABLE prcst, PMEMORY mem);
PPROCESSOR ProcesserQueue_ReleaseOldest(PMEMORY mem, PPROCESSOR_TABLE prcst);
BOOL InitMemoryAndProcesserPrimary(PMEMORY mem, PPROCESSOR_TABLE prcst, BYTE owner, PBYTE data, UINT size);
BOOL InitMemoryAndProcesserSecondary(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR parent);

VOID Processor_RoundProgramCounter(PPROCESSOR prcs);
VOID Processor_IncreceProgramCounter(PPROCESSOR prcs, UINT cnt);
VOID Processor_DecreceProgramCounter(PPROCESSOR prcs);
BOOL Processor_Step(PPROCESSOR prcs, PMEMORY mem, PPROCESSOR_TABLE prcst);
VOID Processor_Dump(PPROCESSOR prcs);

PBYTE Memory_Data(PMEMORY mem, UINT addr);
PBYTE Memory_Owner(PMEMORY mem, UINT addr);

VOID Memory_Init(PMEMORY mem, UINT addr, UINT size);
BOOL FindFreeMemoryAndProcessor(PMEMORY mem, PPROCESSOR_TABLE prcst, UINT size, PUINT addr, PPROCESSOR * prcs);

PMEMORY Memory_Create(UINT size);
VOID Memory_Release(PMEMORY mem);

POWNER_TABLE OwnerTable_Create(UINT size);
VOID OwnerTable_Release(POWNER_TABLE owntbl);
PCONST_CHAR OwnerTable_Name(POWNER_TABLE owntbl, UINT owner);

PWORLD World_Create(PWORLD_PARAM param);
VOID World_Release(PWORLD wld);
VOID World_JudgeResult(PWORLD wld);
BOOL World_Run(PWORLD wld);

BOOL Memory_Write(PMEMORY mem, PPROCESSOR prcs, UINT localaddr, BYTE data);
BYTE Memory_Read(PMEMORY mem, PPROCESSOR prcs, UINT localaddr, PBYTE data);
BOOL Memory_OutOfMemory(PMEMORY mem, UINT addr);

PCONST_CHAR CodeToMnemonic(BYTE code);
UINT MnemonicToCode(PCONST_CHAR mnemonic);
INSTRUCTION_IMPL CodeToImpl(BYTE code);
BOOL StringToUint(PCONST_CHAR s, PUINT value);
BOOL IsLabel(PCONST_CHAR s);

UINT ReadUInt(PBYTE destination);
VOID WriteUInt(PBYTE destination, UINT value);
BOOL ReplaceExtension(PCONST_CHAR source, PCHAR replaced, PCONST_CHAR extension);
BOOL GetAssemblyFilePath(PCONST_CHAR source, PCHAR destination);
BOOL GetLogFilePath(PCONST_CHAR source, PCHAR destination);

PSTRING String_Create(PCONST_CHAR s);
VOID String_Release(PSTRING str);
BOOL String_Reserve(PSTRING str, UINT reserve);
PCHAR String_Data(PSTRING str);
UINT String_Size(PSTRING str);
BOOL String_Copy(PSTRING dst, PSTRING src);
BOOL String_CopyCStr(PSTRING dst, PCONST_CHAR src);
BOOL String_Cat(PSTRING dst, PSTRING src);
UINT String_Comapre(PCONST_STRING dst, PCONST_STRING src);
UINT String_ICompare(PCONST_STRING dst, PCONST_STRING src);

PVECTOR Vector_Create();
VOID Vector_Release(PVECTOR vct);
BOOL Vector_Reserve(PVECTOR vct, UINT reserve);
PVOID Vector_Data(PVECTOR vct);
PUINT Vector_Size(PVECTOR vct);

PCHAR Tokens_CreateFromFile(PCONST_CHAR file);
VOID Tokens_Release(PCHAR tokens);

BOOL Assembly_Reserve(PASSEMBLY asm_, UINT size);
PASSEMBLY Assembly_CreateFromFile(PCONST_CHAR file);
VOID Assembly_Release(PASSEMBLY asm_);
VOID Assembly_Deploy(PMEMORY mem, PASSEMBLY asm_, UINT owner);
BOOL Assembly_CreateFile(PASSEMBLY asm_, PCONST_CHAR path);

INT ScoreOwnerPairComparator(CONST VOID * a, CONST VOID * b);
PCONST_CHAR SuffixString(UINT n);

PSTRING_UINT_MAP StringUIntMap_Create();
VOID StringUIntMap_Release(PSTRING_UINT_MAP suimap);
BOOL StringUIntMap_Add(PSTRING_UINT_MAP suimap, PCONST_CHAR s, UINT ui);
BOOL StringUIntMap_Find(PSTRING_UINT_MAP suimap, PCONST_CHAR s, PUINT ui);

VOID Debug(PCONST_CHAR file, PCONST_CHAR func, UINT line, PCONST_CHAR format, ...);
VOID PrintHelp();
VOID ParseCommandLine(INT argc, PCONST_CHAR * argv);

VOID * NativeMalloc(UINT size)
{
    VOID * tmp;
    
    tmp = malloc(size);
    if (tmp)
        memset(tmp, 0, size);

    return tmp;
}

VOID * NativeRealloc(VOID * ptr, UINT size)
{
    return realloc(ptr, size);
}

VOID NativeFree(VOID * ptr)
{
    free(ptr);
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

BOOL ProcessorTable_Tick(PPROCESSOR_TABLE prcst, PMEMORY mem)
{
    UINT i;
    for (i = 0; i < prcst->size; ++i)
        if (prcst->data[i].owner != SYSTEM)
            if (!Processor_Step(&prcst->data[i], mem, prcst))
                return FALSE;
    return TRUE;
}

PPROCESSOR ProcesserQueue_ReleaseOldest(PMEMORY mem, PPROCESSOR_TABLE prcst)
{
    UINT i, maxused, maxoffset;
    PPROCESSOR oldest;

    maxused = 0;
    maxoffset = 0;
    for (i = 0; i < prcst->size; ++i)
    {
        if (prcst->data[i].used >= maxused)
        {
            maxused = prcst->data[i].used;
            maxoffset = i;
        }
    }

    oldest = &prcst->data[maxoffset];

    for (i = 0; i < oldest->size; ++i)
        *Memory_Owner(mem, oldest->addr + i) = SYSTEM;

    return oldest;
}

BOOL InitMemoryAndProcesserPrimary(PMEMORY mem, PPROCESSOR_TABLE prcst, BYTE owner, PBYTE data, UINT size)
{
#define DEFAULT_RESERVE_MAX 1024

    UINT i, addr;
    PPROCESSOR prcs;

    if (!FindFreeMemoryAndProcessor(mem, prcst, size, &addr, &prcs))
        return FALSE;

    prcs->pid = CreatePID();
    prcs->addr = addr;
    prcs->size = size;
    prcs->pc = 0;
    prcs->sp = size;
    prcs->ptr = 0;
    prcs->rgst = 0;
    prcs->tmp = 0;
    prcs->rsv = 0;
    prcs->rsvmax = DEFAULT_RESERVE_MAX;
    prcs->rsvptr = (PBYTE)NativeMalloc(sizeof(BYTE) * prcs->rsvmax);
    if (!prcs->rsvptr)
        return FALSE;
    prcs->used = 0;
    prcs->owner = owner;

    for (i = 0; i < prcs->size; ++i)
    {
        *Memory_Data(mem, addr + i) = data[i];
        *Memory_Owner(mem, addr + i) = owner;
    }

    return TRUE;

#undef DEFAULT_RESERVE_MAX
}

BOOL InitMemoryAndProcesserSecondary(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR parent)
{
#define DEFAULT_RESERVE_MAX 1024

    UINT i, addr;
    PPROCESSOR prcs;

    if (!FindFreeMemoryAndProcessor(mem, prcst, parent->rsv, &addr, &prcs))
        return FALSE;

    prcs->pid = CreatePID();
    prcs->addr = addr;
    prcs->size = parent->rsv;
    prcs->pc = 0;
    prcs->sp = parent->rsv;
    prcs->ptr = 0;
    prcs->rgst = 0;
    prcs->tmp = 0;
    prcs->rsv = 0;
    prcs->rsvmax = DEFAULT_RESERVE_MAX;
    prcs->rsvptr = (PBYTE)NativeMalloc(sizeof(BYTE) * prcs->rsvmax);
    if (!prcs->rsvptr)
        return FALSE;
    prcs->used = 0;
    prcs->owner = parent->owner;

    for (i = 0; i < prcs->size; ++i)
    {
        *Memory_Data(mem, addr + i) = parent->rsvptr[i];
        *Memory_Owner(mem, addr + i) = parent->owner;
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

BOOL Processor_Step(PPROCESSOR prcs, PMEMORY mem, PPROCESSOR_TABLE prcst)
{
    UINT code;
    code = *Memory_Data(mem, prcs->pc);
    if (code < INSTRUCTION_NUMBER)
        if (!CodeToImpl(code)(mem, prcst, prcs))
            return FALSE;
    ++prcs->used;
    return TRUE;
}

VOID Processor_Dump(PPROCESSOR prcs)
{
    printf("pid  : 0x%08x\n", prcs->pid    );
    printf("addr : 0x%08x\n", prcs->addr   );
    printf("size : 0x%08x\n", prcs->size   );
    printf("pc   : 0x%08x\n", prcs->pc     );
    printf("sp   : 0x%08x\n", prcs->sp     );
    printf("ptr  : 0x%08x\n", prcs->ptr    );
    printf("rgst : 0x%08x\n", prcs->rgst   );
    printf("tmp  : 0x%08x\n", prcs->tmp    );
    printf("rsv  : 0x%08x\n", prcs->rsv    );
    printf("owner: 0x%08x\n", prcs->owner  );
}

PBYTE Memory_Data(PMEMORY mem, UINT addr)
{
    return mem->data + addr;
}

PBYTE Memory_Owner(PMEMORY mem, UINT addr)
{
    return mem->owner + addr;
}

VOID Memory_Init(PMEMORY mem, UINT addr, UINT size)
{
    memset(Memory_Data(mem, addr), 0, sizeof(MEMORY) * size);
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
                    Memory_Init(mem, i, size);
                    *addr = i;
                }
                i += tmp;
            }
            else
            {
                ++i;
            }
        }
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

PCONST_CHAR OwnerTable_Name(POWNER_TABLE owntbl, UINT owner)
{
    return owntbl->data[owner - USER].name;
}

PWORLD World_Create(PWORLD_PARAM param)
{
    PWORLD wld = (PWORLD)NativeMalloc(sizeof(WORLD));
    wld->mem = Memory_Create(param->memory_size);
    wld->prcst = ProcessorTable_Create(param->program_number);
    wld->iteration_number = param->iteration_number;
    wld->owntbl = OwnerTable_Create(param->owner_number);
    return wld;
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

    for (i = 0; i < wld->owntbl->size; ++i)
        pairs[i].owner = i + USER;

    for (i = 0; i < wld->prcst->size; ++i)
        if (wld->prcst->data[i].owner != SYSTEM)
            pairs[wld->prcst->data[i].owner - USER].score += wld->prcst->data[i].size;

    qsort(pairs, wld->owntbl->size, sizeof(SCORE_OWNER_PAIR), ScoreOwnerPairComparator);

    for (i = 0; i < wld->owntbl->size; ++i)
        printf("%d%s %s (%d)\n", i + 1, SuffixString(i + 1), OwnerTable_Name(wld->owntbl, pairs[i].owner), pairs[i].score);

    NativeFree(pairs);
}

BOOL World_Run(PWORLD wld)
{
    UINT i;
    for (i = 0; i < wld->iteration_number; ++i)
        if (!ProcessorTable_Tick(wld->prcst, wld->mem))
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
    return mem->size >= addr;
}

BOOL NOP_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL SEEK_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->ptr = prcs->rgst;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL ADD_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->rgst += prcs->tmp;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL SUB_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->rgst -= prcs->tmp;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL AND_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->rgst &= prcs->tmp;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL OR_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->rgst |= prcs->tmp;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL XOR_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->rgst ^= prcs->tmp;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL NOT_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->rgst = (prcs->rgst != 0) ? 0 : ~0;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL SLA_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->rgst = (prcs->tmp << prcs->rgst) & ~1;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL SRA_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    UINT msb;
    msb = prcs->rgst & 0x80000000;
    prcs->rgst = (prcs->tmp >> prcs->rgst) | msb;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL SLL_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->rgst = (prcs->tmp << prcs->rgst) & 0x8FFFFFFF;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL SRL_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->rgst = (prcs->tmp >> prcs->rgst) & ~1;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL READ_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    UINT i, value;
    BYTE data;

    value = 0;
    for (i = 0; i < sizeof(UINT); ++i)
    {
        if (!Memory_Read(mem, prcs, prcs->ptr, &data))
        {
            prcs->pc = 0;
            return TRUE;
        }
        value |= data << (8 * i);
    }
    prcs->rgst = value;

    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL WRITE_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    UINT i;
    BYTE data;

    for (i = 0; i < sizeof(UINT); ++i)
    {
        data = (BYTE)(prcs->rgst >> (8 * i));
        if (!Memory_Write(mem, prcs, prcs->ptr, data))
        {
            prcs->pc = 0;
            return TRUE;
        }
    }

    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL SAVE_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->tmp = prcs->rgst;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL SWAP_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    UINT tmp;
    tmp = prcs->tmp;
    prcs->tmp = prcs->rgst;
    prcs->rgst = tmp;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL SET_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    UINT i, value;
    BYTE data;

    value = 0;
    for (i = 0; i < sizeof(UINT); ++i)
    {
        if (!Memory_Read(mem, prcs, prcs->pc + 1 + i, &data))
        {
            prcs->pc = 0;
            return TRUE;
        }
        value |= data << (i * 8);
    }
    prcs->rgst = value;
    Processor_IncreceProgramCounter(prcs, 1 + sizeof(UINT));
    return TRUE;
}

BOOL JMP_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    prcs->pc = prcs->rgst;
    Processor_RoundProgramCounter(prcs);
    return TRUE;
}

BOOL JEZ_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    if (prcs->tmp == 0)
        prcs->pc = prcs->rgst;
    Processor_RoundProgramCounter(prcs);
    return TRUE;
}

BOOL PUSH_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    --prcs->sp;
    if (!Memory_Write(mem, prcs, prcs->sp, prcs->rgst))
    {
        prcs->pc = 0;
        return TRUE;
    }
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL POP_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    BYTE data;
    if (!Memory_Read(mem, prcs, prcs->sp, &data))
    {
        prcs->pc = 0;
        return TRUE;
    }
    prcs->rgst = data;
    ++prcs->sp;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL CALL_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    BYTE data;
    if (prcs->pc + 1 >= prcs->size)
    {
        Processor_RoundProgramCounter(prcs);
        return TRUE;
    }
    --prcs->sp;
    if (!Memory_Write(mem, prcs, prcs->sp, prcs->pc + 2))
    {
        prcs->pc = 0;
        return TRUE;
    }
    if (!Memory_Read(mem, prcs, prcs->pc + 1, &data))
    {
        prcs->pc = 0;
        return TRUE;
    }
    prcs->pc = data;
    return TRUE;
}

BOOL RET_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    BYTE data;
    if (!Memory_Read(mem, prcs, prcs->sp, &data))
    {
        prcs->pc = 0;
        return TRUE;
    }
    prcs->pc = data;
    ++prcs->sp;
    Processor_RoundProgramCounter(prcs);
    return TRUE;
}

BOOL RESERVE_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    BYTE data;
    if (prcs->rsv >= prcs->rsvmax)
    {
        prcs->rsvmax *= 2;
        prcs->rsvptr = (PBYTE)NativeRealloc(prcs->rsvptr, sizeof(BYTE) * prcs->rsvmax);
        if (!prcs->rsvptr)
            return FALSE;
        if (!Memory_Read(mem, prcs, prcs->ptr, &data))
        {
            prcs->pc = 0;
            return TRUE;
        }
        prcs->rsvptr[prcs->rsv] = data;
    }
    ++prcs->rsv;
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

BOOL MALLOC_(PMEMORY mem, PPROCESSOR_TABLE prcst, PPROCESSOR prcs)
{
    if (prcs->rsv)
    {
        InitMemoryAndProcesserSecondary(mem, prcst, prcs);
        prcs->rsv = 0;
    }
    Processor_IncreceProgramCounter(prcs, 1);
    return TRUE;
}

INSTRUCTION_INFO instruction_info_table[] = {
#define DECLARE_INSTRUCTION_INFO(s) {TO_STRING(s), s, s##_}
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
    DECLARE_INSTRUCTION_INFO(RESERVE),
    DECLARE_INSTRUCTION_INFO(MALLOC )
#undef DECLARE_INSTRUCTION_INFO
};

PCONST_CHAR CodeToMnemonic(BYTE code)
{
    return instruction_info_table[code].mnemonic;
}

UINT MnemonicToCode(PCONST_CHAR mnemonic)
{
    UINT i;
    for (i = 0; i < sizeof(instruction_info_table) / sizeof(*instruction_info_table); ++i)
        if (stricmp(mnemonic, instruction_info_table[i].mnemonic) == 0)
            return instruction_info_table[i].code;
    return -1;
}

INSTRUCTION_IMPL CodeToImpl(BYTE code)
{
    return instruction_info_table[code].impl;
}

BOOL StringToUint(PCONST_CHAR s, PUINT value)
{
    PCONST_CHAR cur;

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

BOOL IsLabel(PCONST_CHAR s)
{
    UINT len, i;
    len = strlen(s);
    if (len == 0)
        return FALSE;
    if (isdigit(s[0]))
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

BOOL ReplaceExtension(PCONST_CHAR source, PCHAR replaced, PCONST_CHAR extension)
{
    PCONST_CHAR name, ext;

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

BOOL GetAssemblyFilePath(PCONST_CHAR source, PCHAR destination)
{
    return ReplaceExtension(source, destination, ".qs");
}

BOOL GetLogFilePath(PCONST_CHAR source, PCHAR destination)
{
    return ReplaceExtension(source, destination, ".log");
}

PSTRING String_Create(PCONST_CHAR s)
{
#define STRING_DEFAULT_MAX_SIZE 32
    PSTRING str;
 
    str = (PSTRING)NativeMalloc(sizeof(STRING));
    if (!str)
        return NULL;
    
    str->maxsize = STRING_DEFAULT_MAX_SIZE;
    str->data = (PCHAR)NativeMalloc(str->maxsize);
    if (!str->data)
        goto error;

    return str;

error:
    String_Release(str);
    return NULL;
#undef STRING_DEFAULT_MAX_SIZE
}

VOID String_Release(PSTRING str)
{
    if (str)
    {
        NativeFree(str->data);
        NativeFree(str);
    }
}

BOOL String_Reserve(PSTRING str, UINT reserve)
{
    if (reserve <= str->maxsize)
        return TRUE;

    str->maxsize *= 2;
    str->data = (PCHAR)NativeRealloc(str->data, str->maxsize);

    if (!str->data)
        return FALSE;

    return TRUE;
}

PCHAR String_Data(PSTRING str)
{
    return str->data;
}

UINT String_Size(PSTRING str)
{
    return strlen(str->data);
}

BOOL String_Copy(PSTRING dst, PSTRING src)
{
    if (!String_Reserve(dst, String_Size(src) + 1))
        return FALSE;
    memcpy(dst->data, src->data, String_Size(src) + 1);
    return TRUE;
}

BOOL String_CopyCStr(PSTRING dst, PCONST_CHAR src)
{
    if (!String_Reserve(dst, strlen(src) + 1))
        return FALSE;
    memcpy(dst->data, src, strlen(src) + 1);
    return TRUE;
}

BOOL String_Cat(PSTRING dst, PSTRING src)
{
    if (!String_Reserve(dst, String_Size(dst) + String_Size(src) + 1))
        return FALSE;
    memcpy(dst->data + dst->size, src->data, String_Size(src) + 1);
    return TRUE;
}

UINT String_Comapre(PCONST_STRING dst, PCONST_STRING src)
{
    return strcmp(String_Data(dst), String_Data(dst));
}

UINT String_ICompare(PCONST_STRING dst, PCONST_STRING src)
{
    return stricmp(String_Data(dst), String_Data(dst));
}

PVECTOR Vector_Create()
{
#define VECTOR_DEFAULT_MAX_SIZE 16
    PVECTOR vct;

    vct = (PVECTOR)NativeMalloc(sizeof(VECTOR));
    if (!vct)
        return NULL;

    vct->maxsize = VECTOR_DEFAULT_MAX_SIZE;
    vct->data = (PCHAR)NativeMalloc(vct->maxsize);
    if (!vct->data)
        goto error;

    return vct;

error:
    Vector_Release(vct);
    return NULL;
#undef VECTOR_DEFAULT_MAX_SIZE
}

VOID Vector_Release(PVECTOR vct)
{
    if (vct)
    {
        NativeFree(vct->data);
        NativeFree(vct);
    }
}

BOOL Vector_Reserve(PVECTOR vct, UINT reserve)
{
    if (reserve <= vct->maxsize)
        return TRUE;

    vct->maxsize *= 2;
    vct->data = (PVECTOR)NativeRealloc(vct->data, vct->maxsize);

    if (!vct->data)
        return FALSE;

    return TRUE;
}

PVOID Vector_Data(PVECTOR vct)
{
    return vct->data;
}

PUINT Vector_Size(PVECTOR vct)
{
    return &vct->size;
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

PCHAR Tokens_CreateFromFile(PCONST_CHAR file)
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

PASSEMBLY Assembly_CreateFromFile(PCONST_CHAR file)
{
#define DEFAULT_ASSEMBLY_SIZE 1024
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
            DEBUG("label \"%s\" 0x%08x\n", token, asm_->size);
            if (StringUIntMap_Find(label_to_address, token, NULL))
                fprintf(stderr, "already declared label \"%s\"\n", token);
            else if (!StringUIntMap_Add(label_to_address, token, asm_->size))
                goto cleanup;

            token = next_token + 2;
        }
        else if (StringUIntMap_Find(label_to_address, token, &value) || StringToUint(token, &value))
        {
            DEBUG("value 0x%08x\n", value);
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
        DEBUG("pending label \"%s\" 0x%08x is resolved to 0x%08x\n", pending_label->data[i].label, pending_label->data[i].addr, value);
    }

    for (i = 0; i < label_to_address->size; ++i)
    {
        DEBUG("label \"%s\" 0x%08x\n", label_to_address->data[i].label, label_to_address->data[i].addr);
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
#undef DEFAULT_ASSEMBLY_SIZE
}

VOID Assembly_Release(PASSEMBLY asm_)
{
    if (asm_)
    {
        NativeFree(asm_->data);
        NativeFree(asm_);
    }
}

VOID Assembly_Deploy(PMEMORY mem, PASSEMBLY asm_, UINT owner)
{
    UINT i;

    for (i = 0; i < asm_->size; ++i)
    {
        *Memory_Data(mem, i) = asm_->data[i];
        *Memory_Owner(mem, i) = owner;
    }
}

BOOL Assembly_CreateFile(PASSEMBLY asm_, PCONST_CHAR path)
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

PCONST_CHAR SuffixString(UINT n)
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

BOOL StringUIntMap_Add(PSTRING_UINT_MAP suimap, PCONST_CHAR s, UINT ui)
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

BOOL StringUIntMap_Find(PSTRING_UINT_MAP suimap, PCONST_CHAR s, PUINT ui)
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

VOID Debug(PCONST_CHAR file, PCONST_CHAR func, UINT line, PCONST_CHAR format, ...)
{
    va_list args;
    va_start(args, format);

    printf("%s(%d): ", func, line);
    vprintf(format, args);

    va_end(args);
}

VOID PrintHelp()
{
    fprintf(stdin, "");
}

VOID ParseCommandLine(INT argc, PCONST_CHAR * argv)
{
    UINT owner, owner_number;
    PASSEMBLY asm_;
    CHAR asmpath[MAX_PATH];
    PWORLD wld;

    WORLD_PARAM param = {
        1000 * 1000 * 100,
        100,
        1000 * 1000
    };

    memset(asmpath, 0, sizeof(asmpath));

    if (argc == 2)
    {
        PASSEMBLY asm_ = Assembly_CreateFromFile(argv[1]);
        if (asm_)
        {
            memset(asmpath, 0, sizeof(asmpath));
            if (GetAssemblyFilePath(argv[1], asmpath))
                Assembly_CreateFile(asm_, asmpath);
        }
        return;
    }

    if (argc % 2 != 1)
    {
        PrintHelp();
        return;
    }

    wld = World_Create(&param);

    owner_number = (argc - 1) / 2;
    for (owner = 0; owner < owner_number; ++owner)
    {
        strcpy(wld->owntbl->data[owner].name, argv[owner_number * 2]);
        asm_ = Assembly_CreateFromFile(argv[owner_number * 2 + 1]);
        if (asm_)
        {
            Assembly_Deploy(wld->mem, asm_, owner);
            Assembly_Release(asm_);
        }
    }

    if (!World_Run(wld))
    {
        fprintf(stderr, "runtime error\n");
    }
    
    World_JudgeResult(wld);
    World_Release(wld);
}

INT main(INT argc, PCONST_CHAR * argv)
{
    ParseCommandLine(argc, argv);
    return 0;
}

/*

このゲームでは、複数のプレイヤーがメモリにプログラムを配置し自己複製させる。
最終的により多くのメモリを自分のプログラムで埋め尽くしたプレイヤーが勝者となる。

メモリの各番地には、命令セットに含まれるいずれかの値が格納される。
各プレイヤーが自作したプログラムは、ランダムに選択されたメモリに連続して配置される。

プロセッサは以下の要素から構成される。

    プログラムカウンタ
    ポインタ
    レジスタ
    テンポラリレジスタ
    スタックポインタ

プログラムがメモリに配置されるとき、配置されたプログラムにプロセッサが割り当てられる。
プロセッサのプログラムカウンタとポインタは配置されたコードの先頭のアドレスに設定され、
スタックポインタは配置されたコードの末尾のアドレスに設定される。
プロセッサによりプログラムが実行されるたび、プログラムカウンタはひとつインクリメントされる。(JMP, JEZを除く)
プログラムカウンタが配置されたプログラムの範囲を超えた場合、プログラムカウンタは配置されたプログラムの先頭のアドレスに変更される。

命令セットは brainf*ck を参考に設計されている。

    NOP    : 何も行わない。
    SEEK   : ポインタが指すメモリのアドレスをレジスタの値に変更する。
    ADD    : レジスタの値にテンポラリレジスタの値を加算し、レジスタの値をその結果に変更する。
    SUB    : レジスタの値からテンポラリレジスタの値を減算し、レジスタの値をその結果に変更する。
    AND    : レジスタの値とテンポラリレジスタの値でAND演算し、レジスタの値をその結果に変更する。
    OR     : レジスタの値とテンポラリレジスタの値でOR演算し、レジスタの値をその結果に変更する。
    XOR    : レジスタの値とテンポラリレジスタの値でXOR演算し、レジスタの値をその結果に変更する。
    NOT    : レジスタの値が 0 の場合、レジスタの値を全ビット1に設定する。レジスタの値が 1 の場合、レジスタの値を全ビット0に設定する。
    SLA    : テンポラリレジスタの値をレジスタの値で算術左シフト演算し、レジスタの値をその結果に変更する。
    SRA    : テンポラリレジスタの値をレジスタの値で算術右シフト演算し、レジスタの値をその結果に変更する。
    SLL    : テンポラリレジスタの値をレジスタの値で論理左シフト演算し、レジスタの値をその結果に変更する。
    SRL    : テンポラリレジスタの値をレジスタの値で論理右シフト演算し、レジスタの値をその結果に変更する。
    READ   : レジスタの値をポインタが指すメモリの値(4バイト)に変更する。
    WRITE  : ポインタが指すメモリの値(4バイト)をレジスタの値に変更する。
    SAVE   : テンポラリレジスタの値をレジスタの値に変更する。
    SWAP   : レジスタの値とテンポラリレジスタの値を交換する。
    SET    : レジスタを定数に変更する。
    JMP    : プログラムカウンタをレジスタの値に変更する。
    JEZ    : テンポラリレジスタの値が 0 である場合、プログラムカウンタをレジスタの値に変更する。
    PUSH   : スタックポインタを 1 減算し、スタックポインタが指すメモリの値をレジスタの値に変更する。
    POP    : レジスタの値をスタックポインタが指すメモリの値に変更し、スタックポインタを 1 加算する。
    CALL   : スタックポインタを 1 減算し、スタックポインタが指すメモリの値を、プログラムカウンタの値に 2 を加算したアドレスに変更する。
    RET    : プログラムカウンタの値をスタックポインタが指すメモリの値に変更し、スタックポイントを 1 加算する。
    RESERVE: ポインタが指すメモリの値(1バイト)を、次回 MALLOC を実行したときにメモリに配置されるプログラムの末尾に追加する。
    MALLOC : RESERVE により蓄積されたデータを割り当てられたメモリに配置し、プロセッサを割り当てる。

プロセッサが計算において使用するアドレスは、プロセッサが割り当てられているメモリに配置されたプログラムの先頭のアドレスを基準とした相対アドレスとして解釈される。

メモリの読み書きには制限がある。
プログラムに割り当てられたプロセッサは、自身の所有者以外により所有されているプログラムが配置されたメモリに書き込むことができず、読み込むことだけができる。
それ以外のメモリに対しては、読み込みと書き込みの両方ができる。
メモリの読み書きの権限について以下に記載する。

    ・RW 自身の所有者により所有されるプログラムが配置されたメモリ
    ・R- 自身の所有者以外により所有されているプログラムが配置されたメモリ
    ・RW いずれのプログラムも配置されていないメモリ

ここで、プログラムが配置されたメモリは、プログラムに割り当てられたプロセッサの書き込みにより変更することができることに注意する。
「メモリに配置されたプログラムが計算のため使用できるメモリ」と「メモリに配置されたプログラム自身のコード」の間には区別がない。
換言すれば、プログラムは実行時に自己を変更することができる。
これらの仕様から、通常のプログラムの設計においては、計算のために使用するメモリ領域を、プログラムのコード領域に含める必要があるだろう。

このゲームは、特定の回数だけティックが繰り返されることにより実行される。
1ティックの間に、メモリに配置された全てのプログラムは並列に1命令ずつ実行される。
自己複製の処理を複数のプログラムにより分担して実行することができれば、自己複製の速度を向上させることができる。

ゲームが進行すると、いずれのメモリにもプログラムが配置され、そのままでは新しいプログラムを配置することが不可能になる。
また、配置されたプログラムに割り当てることができるプロセッサの数は有限であるため、新しいプロセッサを割り当てることが不可能になることもある。
そのため、プログラムが自己複製を試みる際に空きメモリと空きプロセッサのどちらかが存在しない場合、
システムは最も古くにプログラムを配置したメモリを解放し、そのプログラムに割り当てられていたプロセッサを解放する。
この解放は空きメモリの不足が解消されるまで繰り返される。
解放されたプロセッサは実行されなくなるが、解放されたプロセッサが割り当てられていたメモリに配置されたプログラムはそのまま残る。

このゲームは完全な再現性を有する。
乱数生成の方式は公開され、変更されない。
プログラムが自己複製する際に突然変異は発生しない。

アセンブリは以下のフォーマットで記述する。

SET MYLABEL
JMP
HOGE:
0
FUGA:
0xFF00
MYLABEL:

定数は4バイトの数値として解釈される。
数値に0xを前置すると16進数として解釈される。
:を後置するとラベル名の宣言として解釈される。
ラベル名は宣言されるより以前に使用することができる。
使用されたラベル名は、ラベルが宣言される場所の4バイトのアドレスに展開される。

*/