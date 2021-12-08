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

#define TO_STRING_(s) #s
#define TO_STRING(s) TO_STRING_(s)

#define FORWARD_DECLARATION(type) struct type##_; typedef type##_ type, * P##type;

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

FORWARD_DECLARATION(MEMORY)
FORWARD_DECLARATION(PROGRAM)
FORWARD_DECLARATION(PROGRAM_QUEUE)
FORWARD_DECLARATION(OWNER)
FORWARD_DECLARATION(OWNER_TABLE)
FORWARD_DECLARATION(WORLD)
FORWARD_DECLARATION(WORLD_PARAM)
FORWARD_DECLARATION(INSTRUCTION_INFO)
FORWARD_DECLARATION(ASSEMBLY)
FORWARD_DECLARATION(SCORE_WONER_PAIR)

typedef struct MEMORY_
{
    UINT    size;
    PBYTE   data;
    PBYTE   owner;
} MEMORY, * PMEMORY;

typedef struct PROGRAM_
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
} PROGRAM, * PPROGRAM;

typedef struct PROGRAM_QUEUE_
{
    UINT     size;
    PPROGRAM data;
    UINT     cur;
} PROGRAM_QUEUE, * PPROGRAM_QUEUE;

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
    UINT            size;
    PMEMORY         mem;
    PPROGRAM_QUEUE  pgmq;
    UINT            iteration_number;
    POWNER_TABLE    owntbl;
} WORLD, * PWORLD;

typedef struct WORLD_PARAM_
{
    UINT memory_size;
    UINT program_number;
    UINT iteration_number;
    UINT owner_number;
} WORLD_PARAM, * PWORLD_PARAM;

typedef VOID(*INSTRUCTION_IMPL)(PMEMORY mem, PPROGRAM pgm);

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

VOID * NativeMalloc(UINT size);
VOID * NativeRealloc(VOID * ptr, UINT size);
VOID NativeFree(VOID * ptr);

UINT Random();
BYTE RandomInstruction();

PPROGRAM_QUEUE CreateProgramQueue(UINT size);
VOID ReleaseProgramQueue(PPROGRAM_QUEUE pgmq);
CONST_STRING OwnerName(POWNER_TABLE owntbl, UINT owner);

PBYTE MemoryData(PMEMORY mem, UINT addr);
PBYTE MemoryOwner(PMEMORY mem, UINT addr);

VOID InitMemory(PMEMORY mem, UINT addr, UINT size);
VOID ReleaseOldestProgram(PWORLD wld, PPROGRAM_QUEUE pgmq);
UINT MemoryAllocate(PWORLD wld, UINT size);
VOID InitProgram(PPROGRAM pgm, PWORLD wld, BYTE owner, PBYTE data, UINT size);

PMEMORY CreateMemory(UINT size);
VOID ReleaseMemory(PMEMORY mem);

POWNER_TABLE CreateOwnerTable(UINT size);
VOID ReleaseOwnerTable(POWNER_TABLE owntbl);

PWORLD CreateWorld(PWORLD_PARAM param);
VOID ReleaseWorld(PWORLD wld);

VOID WriteMemory(PMEMORY mem, PPROGRAM pgm, UINT addr, BYTE data);
BYTE ReadMemory(PMEMORY mem, PPROGRAM pgm, UINT addr);

BOOL OutOfMemory(PWORLD wld, UINT addr);
VOID RoundProgramCounter(PPROGRAM pgm);
VOID IncreceProgramCounter(PPROGRAM pgm, UINT cnt);
VOID DecreceProgramCounter(PPROGRAM pgm);

CONST_STRING CodeToMnemonic(BYTE code);
BYTE MnemonicToCode(CONST_STRING mnemonic);
INSTRUCTION_IMPL CodeToImpl(BYTE code);
BOOL StringToUint(CONST_STRING s, PUINT value);

VOID WriteUInt(PBYTE destination, UINT value);
UINT ReadUInt(PBYTE destination);

BOOL ReserveAssembly(PASSEMBLY asm_, UINT size);
PASSEMBLY CreateAssemblyFromFile(CONST_STRING file);
VOID ReleaseAssembly(PASSEMBLY asm_);
VOID DeployAssembly(PMEMORY mem, PASSEMBLY asm_, UINT owner);

VOID Step(PMEMORY mem, PPROGRAM pgm);
VOID Tick(PMEMORY mem, PPROGRAM_QUEUE pgmq);

INT ScoreOwnerPairComparator(CONST VOID * a, CONST VOID * b);
VOID DumpProgram(PPROGRAM pgm);
CONST_STRING SuffixString(UINT n);
VOID JudgeResult(PWORLD wld);
VOID RunWorld(PWORLD wld);
BOOL ReplaceExtension(CONST_STRING source, STRING replaced, CONST_STRING extension);
BOOL GetAssemblyFilePath(CONST_STRING source, STRING destination);
BOOL GetLogFilePath(CONST_STRING source, STRING destination);
BOOL CreateAssemblyFile(PASSEMBLY asm_, CONST_STRING path);
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

PPROGRAM_QUEUE CreateProgramQueue(UINT size)
{
    PPROGRAM_QUEUE pgmq = (PPROGRAM_QUEUE)NativeMalloc(sizeof(PROGRAM_QUEUE));
    pgmq->size = size;
    pgmq->data = (PPROGRAM)NativeMalloc(size * sizeof(PROGRAM));
    return pgmq;
}

VOID ReleaseProgramQueue(PPROGRAM_QUEUE pgmq)
{
    if (pgmq)
    {
        NativeFree(pgmq->data);
        NativeFree(pgmq);
    }
}

CONST_STRING OwnerName(POWNER_TABLE owntbl, UINT owner)
{
    return owntbl->data[owner - USER].name;
}

PBYTE MemoryData(PMEMORY mem, UINT addr)
{
    return mem->data + addr;
}

PBYTE MemoryOwner(PMEMORY mem, UINT addr)
{
    return mem->owner + addr;
}

VOID InitMemory(PMEMORY mem, UINT addr, UINT size)
{
    memset(MemoryData(mem, addr), 0, sizeof(MEMORY) * size);
}

VOID ReleaseOldestProgram(PWORLD wld, PPROGRAM_QUEUE pgmq)
{
    InitMemory(wld->mem, pgmq->data[pgmq->cur].addr, pgmq->data[pgmq->cur].size);
    memset(&pgmq->data[pgmq->cur], 0, sizeof(PROGRAM));
    ++pgmq->cur;
    if (pgmq->cur == pgmq->size)
        pgmq->cur = 0;
}

UINT MemoryAllocate(PWORLD wld, UINT size)
{
    UINT i, tmp;
    i = 0;
    while (TRUE)
    {
        while (i < wld->size)
        {
            if (*MemoryOwner(wld->mem, i) == SYSTEM)
            {
                tmp = 1;
                while (tmp < size && i + tmp < wld->size && *MemoryOwner(wld->mem, i + tmp) == SYSTEM)
                    ++tmp;
                if (tmp == size)
                {
                    InitMemory(wld->mem, i, size);
                    return i;
                }
                i += tmp;
            }
            else
            {
                ++i;
            }
        }
        ReleaseOldestProgram(wld, wld->pgmq);
    }

    return NULL;
}

VOID InitProgram(PPROGRAM pgm, PWORLD wld, BYTE owner, PBYTE data, UINT size)
{
    UINT i;

    pgm->owner = owner;
    pgm->size = size;
    pgm->addr = MemoryAllocate(wld, size);
    for (i = 0; i < size; ++i)
    {
        *MemoryData(wld->mem, pgm->addr) = data[i];
    }
    pgm->ptr = pgm->addr;
}

PMEMORY CreateMemory(UINT size)
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
    ReleaseMemory(mem);
    return NULL;
}

VOID ReleaseMemory(PMEMORY mem)
{
    if (mem)
    {
        NativeFree(mem->data);
        NativeFree(mem->owner);
    }
}

POWNER_TABLE CreateOwnerTable(UINT size)
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
    ReleaseOwnerTable(owntbl);
    return NULL;
}

VOID ReleaseOwnerTable(POWNER_TABLE owntbl)
{
    if (owntbl)
    {
        NativeFree(owntbl->data);
    }
}

PWORLD CreateWorld(PWORLD_PARAM param)
{
    PWORLD wld = (PWORLD)NativeMalloc(sizeof(WORLD));
    wld->mem = CreateMemory(param->memory_size);
    wld->pgmq = CreateProgramQueue(param->program_number);
    wld->iteration_number = param->iteration_number;
    wld->owntbl = CreateOwnerTable(param->owner_number);
    return wld;
}

VOID ReleaseWorld(PWORLD wld)
{
    if (wld)
    {
        ReleaseMemory(wld->mem);
        ReleaseProgramQueue(wld->pgmq);
        ReleaseOwnerTable(wld->owntbl);
        NativeFree(wld);
    }
}

VOID WriteMemory(PMEMORY mem, PPROGRAM pgm, UINT addr, BYTE data)
{
    if (mem->size >= addr)
        return;
    if (pgm->owner == *MemoryOwner(mem, addr))
        *MemoryData(mem, addr) = data;
}

BYTE ReadMemory(PMEMORY mem, PPROGRAM pgm, UINT addr)
{
    if (mem->size >= addr)
        return NOP;
    return *MemoryData(mem, addr);
}

BOOL OutOfMemory(PWORLD wld, UINT addr)
{
    return wld->size >= addr;
}

VOID RoundProgramCounter(PPROGRAM pgm)
{
    if (pgm->addr + pgm->pc >= pgm->size)
        pgm->pc = 0;
}

VOID IncreceProgramCounter(PPROGRAM pgm, UINT cnt)
{
    pgm->pc += cnt;
    RoundProgramCounter(pgm);
}

VOID DecreceProgramCounter(PPROGRAM pgm)
{
    if (pgm->pc == 0)
        pgm->pc = 0;
    else
        --pgm->pc;
}

VOID NOP_(PMEMORY mem, PPROGRAM pgm)
{
    IncreceProgramCounter(pgm, 1);
}

VOID NEXT_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->ptr += pgm->rgst;
    IncreceProgramCounter(pgm, 1);
}

VOID PREV_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->ptr -= pgm->rgst;
    IncreceProgramCounter(pgm, 1);
}

VOID ADD_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst += ReadMemory(mem, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID SUB_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst -= ReadMemory(mem, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID AND_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst &= ReadMemory(mem, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID OR_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst |= ReadMemory(mem, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID XOR_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst ^= ReadMemory(mem, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID NOT_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst = (pgm->rgst != 0) ? 0 : ~0;
    IncreceProgramCounter(pgm, 1);
}

VOID SLA_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst <<= ReadMemory(mem, pgm, pgm->ptr);
    pgm->rgst &= ~1;
    IncreceProgramCounter(pgm, 1);
}

VOID SRA_(PMEMORY mem, PPROGRAM pgm)
{
    UINT msb;
    msb = ReadMemory(mem, pgm, pgm->ptr) & 0x80000000;
    pgm->rgst >>= ReadMemory(mem, pgm, pgm->ptr);
    pgm->rgst |= msb;
    IncreceProgramCounter(pgm, 1);
}

VOID SLL_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst <<= ReadMemory(mem, pgm, pgm->ptr);
    pgm->rgst &= 0x8FFFFFFF;
    IncreceProgramCounter(pgm, 1);
}

VOID SRL_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst >>= ReadMemory(mem, pgm, pgm->ptr);
    pgm->rgst &= ~1;
    IncreceProgramCounter(pgm, 1);
}

VOID READ_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst = ReadMemory(mem, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID WRITE_(PMEMORY mem, PPROGRAM pgm)
{
    WriteMemory(mem, pgm, pgm->ptr, pgm->rgst);
    IncreceProgramCounter(pgm, 1);
}

VOID SAVE_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->tmp = pgm->rgst;
    IncreceProgramCounter(pgm, 1);
}

VOID SWAP_(PMEMORY mem, PPROGRAM pgm)
{
    UINT tmp;
    tmp = pgm->tmp;
    pgm->tmp = pgm->rgst;
    pgm->rgst = tmp;
    IncreceProgramCounter(pgm, 1);
}

VOID SET_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst = ReadMemory(mem, pgm, pgm->pc + 1);
    IncreceProgramCounter(pgm, 2);
}

VOID JMP_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->pc = pgm->rgst;
    RoundProgramCounter(pgm);
}

VOID JEZ_(PMEMORY mem, PPROGRAM pgm)
{
    if (pgm->tmp == 0)
        pgm->pc = pgm->rgst;
    RoundProgramCounter(pgm);
}

VOID PUSH_(PMEMORY mem, PPROGRAM pgm)
{
    --pgm->sp;
    WriteMemory(mem, pgm, pgm->sp, pgm->rgst);
    IncreceProgramCounter(pgm, 1);
}

VOID POP_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->rgst = ReadMemory(mem, pgm, pgm->sp);
    ++pgm->sp;
    IncreceProgramCounter(pgm, 1);
}

VOID CALL_(PMEMORY mem, PPROGRAM pgm)
{
    if (pgm->pc + 1 >= pgm->size)
        return;
    --pgm->sp;
    WriteMemory(mem, pgm, pgm->sp, pgm->pc + 2);
    pgm->pc = ReadMemory(mem, pgm, pgm->pc + 1);
}

VOID RET_(PMEMORY mem, PPROGRAM pgm)
{
    pgm->pc = ReadMemory(mem, pgm, pgm->sp);
    ++pgm->sp;
    RoundProgramCounter(pgm);
}

VOID PREPARE_(PMEMORY mem, PPROGRAM pgm)
{
    IncreceProgramCounter(pgm, 1);
}

VOID MALLOC_(PMEMORY mem, PPROGRAM pgm)
{
    IncreceProgramCounter(pgm, 1);
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

VOID WriteUInt(PBYTE destination, UINT value)
{
    UINT i;
    for (i = 0; i < sizeof(UINT); ++i)
        destination[i] = ((value >> (8 * i)) & 0xff);
}

UINT ReadUInt(PBYTE destination)
{
    UINT i, value;
    value = 0;
    for (i = 0; i < sizeof(UINT); ++i)
        value |= destination[i] << (8 * (sizeof(UINT) - 1 - i));
    return value;
}

BOOL ReserveAssembly(PASSEMBLY asm_, UINT size)
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
PASSEMBLY CreateAssemblyFromFile(CONST_STRING file)
{
    printf("file=%s\n", file);
    PASSEMBLY asm_;
    FILE * fp;
    CHAR mnemonic[LINE_LENGTH];
    BYTE code;
    UINT value;
    BOOL valid;

    valid = FALSE;

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
    
    while (TRUE)
    {
        if (fscanf(fp, "%" TO_STRING(LINE_LENGTH_FORMAT) "s[a-zA-Z0-9]%c*", mnemonic, &code) == EOF)
            break;

        if (StringToUint(mnemonic, &value))
        {
            printf("value=%d\n", value);
            if (!ReserveAssembly(asm_, asm_->size + sizeof(value)))
                goto cleanup;
            WriteUInt(&asm_->data[asm_->size], value);
            asm_->size += sizeof(value);
        }
        else
        {
            code = MnemonicToCode(mnemonic);
            if (code == -1)
                goto cleanup;
            printf("code=%d\n", code);
            if (!ReserveAssembly(asm_, asm_->size + sizeof(code)))
                goto cleanup;
            asm_->data[asm_->size] = code;
            asm_->size += sizeof(code);
        }
    }

    valid = TRUE;

cleanup:
    fclose(fp);

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

VOID ReleaseAssembly(PASSEMBLY asm_)
{
    if (asm_)
    {
        NativeFree(asm_->data);
        NativeFree(asm_);
    }
}

VOID DeployAssembly(PMEMORY mem, PASSEMBLY asm_, UINT owner)
{
    UINT i;

    for (i = 0; i < asm_->size; ++i)
    {
        *MemoryData(mem, i) = asm_->data[i];
        *MemoryOwner(mem, i) = owner;
    }
}

VOID Step(PMEMORY mem, PPROGRAM pgm)
{
    UINT code;
    code = *MemoryData(mem, pgm->pc);
    if (code < INSTRUCTION_NUMBER)
        CodeToImpl(code)(mem, pgm);
}

VOID Tick(PMEMORY mem, PPROGRAM_QUEUE pgmq)
{
    UINT i;
    for (i = 0; i < pgmq->size; ++i)
        if (pgmq->data[i].owner != SYSTEM)
            Step(mem, &pgmq->data[i]);
}

INT ScoreOwnerPairComparator(CONST VOID * a, CONST VOID * b)
{
    return ((PSCORE_OWNER_PAIR)b)->score - ((PSCORE_OWNER_PAIR)a)->score;
}

VOID DumpProgram(PPROGRAM pgm)
{
    printf("pid  : %x\n", pgm->pid  );
    printf("addr : %x\n", pgm->addr );
    printf("size : %x\n", pgm->size );
    printf("pc   : %x\n", pgm->pc   );
    printf("sp   : %x\n", pgm->sp   );
    printf("ptr  : %x\n", pgm->ptr  );
    printf("rgst : %x\n", pgm->rgst );
    printf("tmp  : %x\n", pgm->tmp  );
    printf("owner: %x\n", pgm->owner);
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

VOID JudgeResult(PWORLD wld)
{
    UINT i;
    PSCORE_OWNER_PAIR pairs;
    
    pairs = (PSCORE_OWNER_PAIR)NativeMalloc(wld->owntbl->size * sizeof(SCORE_OWNER_PAIR));

    for (i = 0; i < wld->owntbl->size; ++i)
        pairs[i].owner = i + USER;

    for (i = 0; i < wld->pgmq->size; ++i)
        if (wld->pgmq->data[i].owner != SYSTEM)
            pairs[wld->pgmq->data[i].owner - USER].score += wld->pgmq->data[i].size;

    qsort(pairs, wld->owntbl->size, sizeof(SCORE_OWNER_PAIR), ScoreOwnerPairComparator);

    for (i = 0; i < wld->owntbl->size; ++i)
        printf("%d%s %s (%d)\n", i + 1, SuffixString(i + 1), OwnerName(wld->owntbl, pairs[i].owner), pairs[i].score);

    NativeFree(pairs);
}

VOID RunWorld(PWORLD wld)
{
    UINT i;
    for (i = 0; i < wld->iteration_number; ++i)
        Tick(wld->mem, wld->pgmq);
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

BOOL CreateAssemblyFile(PASSEMBLY asm_, CONST_STRING path)
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

    if (argc == 2)
    {
        PASSEMBLY asm_ = CreateAssemblyFromFile(argv[1]);
        if (asm_)
        {
            memset(asmpath, 0, sizeof(asmpath));
            if (GetAssemblyFilePath(argv[1], asmpath))
                CreateAssemblyFile(asm_, asmpath);
        }
        return;
    }

    if (argc % 2 != 1)
    {
        PrintHelp();
        return;
    }

    wld = CreateWorld(&param);

    owner_number = (argc - 1) / 2;
    for (owner = 0; owner < owner_number; ++owner)
    {
        strcpy(wld->owntbl->data[owner].name, argv[owner_number * 2]);
        asm_ = CreateAssemblyFromFile(argv[owner_number * 2 + 1]);
        if (asm_)
        {
            DeployAssembly(wld->mem, asm_, owner);
            ReleaseAssembly(asm_);
        }
    }

    RunWorld(wld);
    JudgeResult(wld);
    ReleaseWorld(wld);
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

プログラムは以下の要素から構成される。

    プログラムカウンタ
    ポインタ
    レジスタ
    テンポラリレジスタ
    スタックポインタ

プログラムのコードがメモリに配置されるとき、
プログラムカウンタとポインタは配置されたコードの先頭のアドレスに設定され、
スタックポインタは配置されたコードの末尾のアドレスに設定される。
プログラムのコードが実行されるたび、プログラムカウンタはひとつインクリメントされる。(JMP, JEZを除く)
プログラムカウンタがプログラムのコードの範囲を超えた場合、プログラムカウンタは配置されたコードの先頭を指すよう設定される。

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
メモリに配置されたプログラムは、自身の所有者以外により所有されているプログラムが配置されたメモリに書き込むことができず、読み込むことだけができる。
それ以外のメモリに対しては、読み込みと書き込みの両方ができる。
メモリの読み書きの権限について以下に記載する。

    ・RW 自身の所有者により所有されるプログラムが配置されたメモリ
    ・R- 自身の所有者以外により所有されているプログラムが配置されたメモリ
    ・RW いずれのプログラムも配置されていないメモリ

ここで、プログラム自身が配置されたメモリは、プログラム自身の書き込みにより変更することができることに注意する。
「メモリに配置されたプログラムが計算のため使用できるメモリ」と「メモリに配置されたプログラム自身のコード」の間には区別がない。
換言すれば、プログラムは実行時に自己を変更することができる。
これらの仕様から、通常のプログラムの設計においては、計算のために使用するメモリ領域を、プログラムのコード領域に含める必要があるだろう。

このゲームは、特定の回数だけティックが繰り返されることにより実行される。
1ティックの間に、メモリに配置された全てのプログラムは並列に1命令ずつ実行される。
自己複製の処理を複数のプログラムにより分担して実行することができれば、自己複製の速度を向上させることができる。

ゲームが進行すると、いずれのメモリにもプログラムが配置され、そのままでは新しいプログラムを配置することが不可能になる。
そのため、プログラムが自己複製を試みる際に空きメモリが不足していた場合、システムは最も古くに配置されたプログラムを破棄する。
この破棄は空きメモリの不足が解消されるまで繰り返される。
破棄されたプログラムは実行されなくなるが、メモリに配置されたコードはそのまま残る。

このゲームは完全な再現性を有する。
乱数生成の方式は公開され、変更されない。
プログラムが自己複製する際に突然変異は発生しない。

アセンブリは以下のフォーマットで記述する

SET 1
PUSH
POP

*/