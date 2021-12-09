#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#define CONST const
#define VOID void

typedef unsigned char BYTE, * PBYTE;
typedef unsigned char BOOL;
typedef unsigned int UINT, * PUINT;
typedef int INT, * PINT;
typedef char CHAR, * PCHAR, * STRING;
typedef CONST CHAR * CONST_STRING;

#define TRUE  1
#define FALSE 0
#define MAX_PATH 260
#define MAX_LABEL 36

#define TO_STRING_(s) #s
#define TO_STRING(s) TO_STRING_(s)

enum
{
    SYSTEM = 0,
    USER   = 1
};

enum INSTRUCTION
{
    NOP    ,
    NEXT   ,
    PREV   ,
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
    PREPARE,
    MALLOC ,
    INSTRUCTION_NUMBER
};

#define FORWARD_DECLARATION(type) struct type##_; typedef type##_ type, * P##type
    FORWARD_DECLARATION(MEMORY          );
    FORWARD_DECLARATION(PROCESSOR       );
    FORWARD_DECLARATION(PROCESSOR_QUEUE );
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
    UINT    rgst;
    UINT    tmp;
    BYTE    owner;
} PROCESSOR, * PPROCESSOR;

typedef struct PROCESSOR_QUEUE_
{
    UINT        size;
    PPROCESSOR  data;
    UINT        cur;
} PROCESSOR_QUEUE, * PPROCESSOR_QUEUE;

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
    PPROCESSOR_QUEUE    prcsq;
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

typedef VOID(*INSTRUCTION_IMPL)(PMEMORY mem, PPROCESSOR prcs);

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

VOID * NativeMalloc(UINT size);
VOID * NativeRealloc(VOID * ptr, UINT size);
VOID NativeFree(VOID * ptr);

UINT Random();
BYTE RandomInstruction();

PPROCESSOR_QUEUE ProcessorQueue_Create(UINT size);
VOID ProcessorQueue_Release(PPROCESSOR_QUEUE prcsq);

VOID Processor_Init(PPROCESSOR prcs, PMEMORY mem, PPROCESSOR_QUEUE prcsq, BYTE owner, PBYTE data, UINT size);
VOID Processor_RoundProgramCounter(PPROCESSOR prcs);
VOID Processor_IncreceProgramCounter(PPROCESSOR prcs, UINT cnt);
VOID Processor_DecreceProgramCounter(PPROCESSOR prcs);
VOID Processor_Step(PPROCESSOR prcs, PMEMORY mem);
VOID Processor_Tick(PPROCESSOR_QUEUE prcsq, PMEMORY mem);
VOID Processor_Dump(PPROCESSOR prcs);

PBYTE Memory_Data(PMEMORY mem, UINT addr);
PBYTE Memory_Owner(PMEMORY mem, UINT addr);

VOID Memory_Init(PMEMORY mem, UINT addr, UINT size);
VOID ReleaseOldestProgram(PMEMORY mem, PPROCESSOR_QUEUE prcsq);
UINT Memory_Allocate(PMEMORY mem, PPROCESSOR_QUEUE prcsq, UINT size);

PMEMORY Memory_Create(UINT size);
VOID Memory_Release(PMEMORY mem);

POWNER_TABLE OwnerTable_Create(UINT size);
VOID OwnerTable_Release(POWNER_TABLE owntbl);
CONST_STRING OwnerTable_Name(POWNER_TABLE owntbl, UINT owner);

PWORLD World_Create(PWORLD_PARAM param);
VOID World_Release(PWORLD wld);
VOID World_JudgeResult(PWORLD wld);
VOID World_Run(PWORLD wld);

VOID Memory_Write(PMEMORY mem, PPROCESSOR prcs, UINT addr, BYTE data);
BYTE Memory_Read(PMEMORY mem, PPROCESSOR prcs, UINT addr);
BOOL Memory_OutOfMemory(PMEMORY mem, UINT addr);

CONST_STRING CodeToMnemonic(BYTE code);
BYTE MnemonicToCode(CONST_STRING mnemonic);
INSTRUCTION_IMPL CodeToImpl(BYTE code);
BOOL StringToUint(CONST_STRING s, PUINT value);
BOOL IsLabelDeclaration(CONST_STRING s);

UINT ReadUInt(PBYTE destination);
VOID WriteUInt(PBYTE destination, UINT value);
BOOL ReplaceExtension(CONST_STRING source, STRING replaced, CONST_STRING extension);
BOOL GetAssemblyFilePath(CONST_STRING source, STRING destination);
BOOL GetLogFilePath(CONST_STRING source, STRING destination);

BOOL Assembly_Reserve(PASSEMBLY asm_, UINT size);
PASSEMBLY Assembly_CreateFromFile(CONST_STRING file);
VOID Assembly_Release(PASSEMBLY asm_);
VOID Assembly_Deploy(PMEMORY mem, PASSEMBLY asm_, UINT owner);
BOOL Assembly_CreateFile(PASSEMBLY asm_, CONST_STRING path);

INT ScoreOwnerPairComparator(CONST VOID * a, CONST VOID * b);
CONST_STRING SuffixString(UINT n);

PSTRING_UINT_MAP StringUIntMap_Create();
VOID StringUIntMap_Release(PSTRING_UINT_MAP suimap);
BOOL StringUIntMap_Add(PSTRING_UINT_MAP suimap, CONST_STRING s, UINT ui);
BOOL StringUIntMap_Find(PSTRING_UINT_MAP suimap, CONST_STRING s, PUINT ui);

VOID PrintHelp();
VOID ParseCommandLine(INT argc, CONST_STRING * argv);

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

PPROCESSOR_QUEUE ProcessorQueue_Create(UINT size)
{
    PPROCESSOR_QUEUE prcsq = (PPROCESSOR_QUEUE)NativeMalloc(sizeof(PROCESSOR_QUEUE));
    prcsq->size = size;
    prcsq->data = (PPROCESSOR)NativeMalloc(size * sizeof(PROCESSOR));
    return prcsq;
}

VOID ProcessorQueue_Release(PPROCESSOR_QUEUE prcsq)
{
    if (prcsq)
    {
        NativeFree(prcsq->data);
        NativeFree(prcsq);
    }
}

VOID Processor_Init(PPROCESSOR prcs, PMEMORY mem, PPROCESSOR_QUEUE prcsq, BYTE owner, PBYTE data, UINT size)
{
    UINT i;

    prcs->owner = owner;
    prcs->size = size;
    prcs->addr = Memory_Allocate(mem, prcsq, size);
    for (i = 0; i < size; ++i)
    {
        *Memory_Data(mem, prcs->addr) = data[i];
    }
    prcs->ptr = prcs->addr;
}

VOID Processor_RoundProgramCounter(PPROCESSOR prcs)
{
    if (prcs->addr + prcs->pc >= prcs->size)
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

VOID Processor_Step(PPROCESSOR prcs, PMEMORY mem)
{
    UINT code;
    code = *Memory_Data(mem, prcs->pc);
    if (code < INSTRUCTION_NUMBER)
        CodeToImpl(code)(mem, prcs);
}

VOID Processor_Tick(PPROCESSOR_QUEUE prcsq, PMEMORY mem)
{
    UINT i;
    for (i = 0; i < prcsq->size; ++i)
        if (prcsq->data[i].owner != SYSTEM)
            Processor_Step(&prcsq->data[i], mem);
}

VOID Processor_Dump(PPROCESSOR prcs)
{
    printf("pid  : %x\n", prcs->pid  );
    printf("addr : %x\n", prcs->addr );
    printf("size : %x\n", prcs->size );
    printf("pc   : %x\n", prcs->pc   );
    printf("sp   : %x\n", prcs->sp   );
    printf("ptr  : %x\n", prcs->ptr  );
    printf("rgst : %x\n", prcs->rgst );
    printf("tmp  : %x\n", prcs->tmp  );
    printf("owner: %x\n", prcs->owner);
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

VOID ReleaseOldestProgram(PMEMORY mem, PPROCESSOR_QUEUE prcsq)
{
    Memory_Init(mem, prcsq->data[prcsq->cur].addr, prcsq->data[prcsq->cur].size);
    memset(&prcsq->data[prcsq->cur], 0, sizeof(PROCESSOR));
    ++prcsq->cur;
    if (prcsq->cur == prcsq->size)
        prcsq->cur = 0;
}

UINT Memory_Allocate(PMEMORY mem, PPROCESSOR_QUEUE prcsq, UINT size)
{
    UINT i, tmp;
    i = 0;
    while (TRUE)
    {
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
                    return i;
                }
                i += tmp;
            }
            else
            {
                ++i;
            }
        }
        ReleaseOldestProgram(mem, prcsq);
    }

    return NULL;
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

CONST_STRING OwnerTable_Name(POWNER_TABLE owntbl, UINT owner)
{
    return owntbl->data[owner - USER].name;
}

PWORLD World_Create(PWORLD_PARAM param)
{
    PWORLD wld = (PWORLD)NativeMalloc(sizeof(WORLD));
    wld->mem = Memory_Create(param->memory_size);
    wld->prcsq = ProcessorQueue_Create(param->program_number);
    wld->iteration_number = param->iteration_number;
    wld->owntbl = OwnerTable_Create(param->owner_number);
    return wld;
}

VOID World_Release(PWORLD wld)
{
    if (wld)
    {
        Memory_Release(wld->mem);
        ProcessorQueue_Release(wld->prcsq);
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

    for (i = 0; i < wld->prcsq->size; ++i)
        if (wld->prcsq->data[i].owner != SYSTEM)
            pairs[wld->prcsq->data[i].owner - USER].score += wld->prcsq->data[i].size;

    qsort(pairs, wld->owntbl->size, sizeof(SCORE_OWNER_PAIR), ScoreOwnerPairComparator);

    for (i = 0; i < wld->owntbl->size; ++i)
        printf("%d%s %s (%d)\n", i + 1, SuffixString(i + 1), OwnerTable_Name(wld->owntbl, pairs[i].owner), pairs[i].score);

    NativeFree(pairs);
}

VOID World_Run(PWORLD wld)
{
    UINT i;
    for (i = 0; i < wld->iteration_number; ++i)
        Processor_Tick(wld->prcsq, wld->mem);
}

VOID Memory_Write(PMEMORY mem, PPROCESSOR prcs, UINT addr, BYTE data)
{
    if (mem->size >= addr)
        return;
    if (prcs->owner == *Memory_Owner(mem, addr))
        *Memory_Data(mem, addr) = data;
}

BYTE Memory_Read(PMEMORY mem, PPROCESSOR prcs, UINT addr)
{
    if (mem->size >= addr)
        return NOP;
    return *Memory_Data(mem, addr);
}

BOOL Memory_OutOfMemory(PMEMORY mem, UINT addr)
{
    return mem->size >= addr;
}

VOID NOP_(PMEMORY mem, PPROCESSOR prcs)
{
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID NEXT_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->ptr += prcs->rgst;
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID PREV_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->ptr -= prcs->rgst;
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID ADD_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst += Memory_Read(mem, prcs, prcs->ptr);
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID SUB_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst -= Memory_Read(mem, prcs, prcs->ptr);
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID AND_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst &= Memory_Read(mem, prcs, prcs->ptr);
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID OR_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst |= Memory_Read(mem, prcs, prcs->ptr);
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID XOR_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst ^= Memory_Read(mem, prcs, prcs->ptr);
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID NOT_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst = (prcs->rgst != 0) ? 0 : ~0;
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID SLA_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst <<= Memory_Read(mem, prcs, prcs->ptr);
    prcs->rgst &= ~1;
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID SRA_(PMEMORY mem, PPROCESSOR prcs)
{
    UINT msb;
    msb = Memory_Read(mem, prcs, prcs->ptr) & 0x80000000;
    prcs->rgst >>= Memory_Read(mem, prcs, prcs->ptr);
    prcs->rgst |= msb;
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID SLL_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst <<= Memory_Read(mem, prcs, prcs->ptr);
    prcs->rgst &= 0x8FFFFFFF;
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID SRL_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst >>= Memory_Read(mem, prcs, prcs->ptr);
    prcs->rgst &= ~1;
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID READ_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst = Memory_Read(mem, prcs, prcs->ptr);
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID WRITE_(PMEMORY mem, PPROCESSOR prcs)
{
    Memory_Write(mem, prcs, prcs->ptr, prcs->rgst);
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID SAVE_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->tmp = prcs->rgst;
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID SWAP_(PMEMORY mem, PPROCESSOR prcs)
{
    UINT tmp;
    tmp = prcs->tmp;
    prcs->tmp = prcs->rgst;
    prcs->rgst = tmp;
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID SET_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst = Memory_Read(mem, prcs, prcs->pc + 1);
    Processor_IncreceProgramCounter(prcs, 2);
}

VOID JMP_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->pc = prcs->rgst;
    Processor_RoundProgramCounter(prcs);
}

VOID JEZ_(PMEMORY mem, PPROCESSOR prcs)
{
    if (prcs->tmp == 0)
        prcs->pc = prcs->rgst;
    Processor_RoundProgramCounter(prcs);
}

VOID PUSH_(PMEMORY mem, PPROCESSOR prcs)
{
    --prcs->sp;
    Memory_Write(mem, prcs, prcs->sp, prcs->rgst);
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID POP_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->rgst = Memory_Read(mem, prcs, prcs->sp);
    ++prcs->sp;
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID CALL_(PMEMORY mem, PPROCESSOR prcs)
{
    if (prcs->pc + 1 >= prcs->size)
        return;
    --prcs->sp;
    Memory_Write(mem, prcs, prcs->sp, prcs->pc + 2);
    prcs->pc = Memory_Read(mem, prcs, prcs->pc + 1);
}

VOID RET_(PMEMORY mem, PPROCESSOR prcs)
{
    prcs->pc = Memory_Read(mem, prcs, prcs->sp);
    ++prcs->sp;
    Processor_RoundProgramCounter(prcs);
}

VOID PREPARE_(PMEMORY mem, PPROCESSOR prcs)
{
    Processor_IncreceProgramCounter(prcs, 1);
}

VOID MALLOC_(PMEMORY mem, PPROCESSOR prcs)
{
    Processor_IncreceProgramCounter(prcs, 1);
}

#define DECLARE_INSTRUCTION_INFO(s) {TO_STRING(s), s, s##_}
INSTRUCTION_INFO instruction_info_table[] = {
    DECLARE_INSTRUCTION_INFO(NOP    ),
    DECLARE_INSTRUCTION_INFO(NEXT   ),
    DECLARE_INSTRUCTION_INFO(PREV   ),
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
    DECLARE_INSTRUCTION_INFO(PREPARE),
    DECLARE_INSTRUCTION_INFO(MALLOC )
};
#undef DECLARE_INSTRUCTION_INFO

CONST_STRING CodeToMnemonic(BYTE code)
{
    return instruction_info_table[code].mnemonic;
}

BYTE MnemonicToCode(CONST_STRING mnemonic)
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

BOOL StringToUint(CONST_STRING s, PUINT value)
{
    CONST_STRING cur;

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

BOOL IsLabelDeclaration(CONST_STRING s)
{
    if (*s != ':')
        return FALSE;
    for (++s; isalnum(*s); ++s);
    return *s ? FALSE : TRUE;
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

BOOL ReplaceExtension(CONST_STRING source, STRING replaced, CONST_STRING extension)
{
    CONST_STRING name, ext;

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

BOOL GetAssemblyFilePath(CONST_STRING source, STRING destination)
{
    return ReplaceExtension(source, destination, ".qs");
}

BOOL GetLogFilePath(CONST_STRING source, STRING destination)
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

#define DEFAULT_ASSEMBLY_SIZE 1024
#define LINE_LENGTH_FORMAT 1024
#define LINE_LENGTH (LINE_LENGTH_FORMAT + 1)
PASSEMBLY Assembly_CreateFromFile(CONST_STRING file)
{
    PASSEMBLY asm_;
    FILE * fp;
    CHAR data[LINE_LENGTH];
    BYTE code;
    UINT value;
    BOOL valid;
    PSTRING_UINT_MAP suimap;

    valid = FALSE;
    asm_ = NULL;
    suimap = NULL;

    fp = fopen(file, "rb");
    if (!fp)
        return NULL;

    asm_ = (PASSEMBLY)NativeMalloc(sizeof(ASSEMBLY));
    if (!asm_)
        goto cleanup;

    asm_->data = (PBYTE)NativeMalloc(sizeof(BYTE) * DEFAULT_ASSEMBLY_SIZE);
    asm_->maxsize = DEFAULT_ASSEMBLY_SIZE;
    if (!asm_->data)
        goto cleanup;

    suimap = StringUIntMap_Create();
    if (!suimap)
        goto cleanup;
    
    while (TRUE)
    {
        if (fscanf(fp, "%" TO_STRING(LINE_LENGTH_FORMAT) "s[a-zA-Z0-9:]%c*", data, &code) == EOF)
            break;

        if (IsLabelDeclaration(data))
        {
            if (StringUIntMap_Find(suimap, data + 1, NULL))
                fprintf(stderr, "Already declared label %s\n", data + 1);
            else
                StringUIntMap_Add(suimap, data + 1, asm_->size);
        }
        else if (StringUIntMap_Find(suimap, data + 1, &value) || StringToUint(data, &value))
        {
            if (!Assembly_Reserve(asm_, asm_->size + sizeof(value)))
                goto cleanup;
            WriteUInt(&asm_->data[asm_->size], value);
            asm_->size += sizeof(value);
        }
        else
        {
            code = MnemonicToCode(data);
            if (code == -1)
                goto cleanup;
            if (!Assembly_Reserve(asm_, asm_->size + sizeof(code)))
                goto cleanup;
            asm_->data[asm_->size] = code;
            asm_->size += sizeof(code);
        }
    }

    valid = TRUE;

cleanup:
    fclose(fp);

    StringUIntMap_Release(suimap);

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
}
#undef LINE_LENGTH
#undef LINE_LENGTH_FORMAT
#undef DEFAULT_ASSEMBLY_SIZE

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

BOOL Assembly_CreateFile(PASSEMBLY asm_, CONST_STRING path)
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

CONST_STRING SuffixString(UINT n)
{
    if (n == 1)
        return "st";
    if (n == 2)
        return "nd";
    if (n == 3)
        return "rd";
    return "th";
}

#define STRING_UINT_MAP_DEFAULT_MAX_SIZE 256
PSTRING_UINT_MAP StringUIntMap_Create()
{
    PSTRING_UINT_MAP suimap;

    suimap = (PSTRING_UINT_MAP)NativeMalloc(sizeof(STRING_UINT_MAP));
    if (!suimap)
        return NULL;
    
    suimap->data = (PSTRING_UINT_PAIR)NativeMalloc(sizeof(STRING_UINT_PAIR) * STRING_UINT_MAP_DEFAULT_MAX_SIZE);
    if (!suimap->data)
        goto error;
    suimap->maxsize = STRING_UINT_MAP_DEFAULT_MAX_SIZE;

    return suimap;

error:
    StringUIntMap_Release(suimap);
    return NULL;
}

VOID StringUIntMap_Release(PSTRING_UINT_MAP suimap)
{
    if (suimap)
    {
        NativeFree(suimap->data);
        NativeFree(suimap);
    }
}

BOOL StringUIntMap_Add(PSTRING_UINT_MAP suimap, CONST_STRING s, UINT ui)
{
    if (suimap->size >= suimap->maxsize)
    {
        suimap->maxsize *= 2;
        suimap->data = (PSTRING_UINT_PAIR)NativeRealloc(suimap->data, suimap->maxsize);
        return FALSE;
    }

    strcpy(suimap->data[suimap->size].label, s);
    suimap->data[suimap->size].addr = ui;
    ++suimap->size;
    return TRUE;
}

BOOL StringUIntMap_Find(PSTRING_UINT_MAP suimap, CONST_STRING s, PUINT ui)
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

VOID PrintHelp()
{
    fprintf(stdin, "");
}

VOID ParseCommandLine(INT argc, CONST_STRING * argv)
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

    World_Run(wld);
    World_JudgeResult(wld);
    World_Release(wld);
}

INT main(INT argc, CONST_STRING * argv)
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
    NEXT   : ポインタが指すメモリのアドレスにレジスタの値を加算する。
    PREV   : ポインタが指すメモリのアドレスにレジスタの値を減算する。
    ADD    : レジスタの値にポインタが指すメモリの値を加算する。
    SUB    : レジスタの値にポインタが指すメモリの値を減算する。
    AND    : レジスタの値にポインタが指すメモリの値をAND演算する。
    OR     : レジスタの値にポインタが指すメモリの値をOR演算する。
    XOR    : レジスタの値にポインタが指すメモリの値をXOR演算する。
    NOT    : レジスタの値が 0 の場合、レジスタの値を全ビット1に設定する。レジスタの値が 1 の場合、レジスタの値を全ビット0に設定する。
    SLA    : レジスタの値をポインタが指すメモリの値で算術左シフト演算する。
    SRA    : レジスタの値をポインタが指すメモリの値で算術右シフト演算する。
    SLL    : レジスタの値をポインタが指すメモリの値で論理左シフト演算する。
    SRL    : レジスタの値をポインタが指すメモリの値で論理右シフト演算する。
    READ   : レジスタの値をポインタが指すメモリの値に変更する。
    WRITE  : ポインタが指すメモリの値をレジスタの値に変更する。
    SAVE   : テンポラリレジスタの値をレジスタの値に変更する。
    SWAP   : レジスタの値とテンポラリレジスタの値を交換する。
    SET    : レジスタを定数に変更する。
    JMP    : プログラムカウンタをレジスタの値に変更する。
    JEZ    : テンポラリレジスタの値が 0 である場合、プログラムカウンタをレジスタの値に変更する。
    PUSH   : スタックポインタを 1 減算し、レジスタの値をスタックポインタが指すメモリの値に変更する。
    POP    : レジスタの値をスタックポインタが指すメモリの値に変更し、スタックポインタを 1 加算する。
    CALL   : スタックポインタを 1 減算し、スタックポインタが指すメモリの値を、プログラムカウンタの値に 2 を加算したアドレスに変更する。
    RET    : プログラムカウンタの値をスタックポインタが指すメモリの値に変更し、スタックポイントを 1 加算する。
    PREPARE: 次回 MALLOC を実行した際に割り当てられるメモリの大きさをインクリメントする。
    MALLOC : 前回 MALLOC が呼び出されてから現在までに PREPARE が実行された回数分の大きさのメモリを確保する。
             レジスタの値を確保されたメモリの先頭のアドレスに変更する。
             スタックポインタの値を確保されたメモリの末尾に変更する。

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
そのため、プログラムが自己複製を試みる際に空きメモリが不足していた場合、
システムは最も古くにプログラムを配置したメモリを解放し、そのプログラムに割り当てられていたプロセッサを解放する。
この解放は空きメモリの不足が解消されるまで繰り返される。
解放されたプロセッサは実行されなくなり、解放されたメモリに配置されたプログラムはそのまま残る。

このゲームは完全な再現性を有する。
乱数生成の方式は公開され、変更されない。
プログラムが自己複製する際に突然変異は発生しない。

アセンブリは以下のフォーマットで記述する

SET 1
PUSH
POP

*/