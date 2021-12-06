#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef unsigned char BYTE, * PBYTE;
typedef unsigned char BOOL;
typedef unsigned int UINT, * PUINT;
typedef char CHAR, * PCHAR;

#define TRUE  1
#define FALSE 0
#define MAX_PATH 260
#define CONST const
#define VOID void

#define STRING_(s) #s
#define STRING(s) STRING_(s)

enum OWNER
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

typedef VOID(*INSTRUCTION_IMPL)(PWORLD wld, PPROGRAM pgm);

typedef struct MEMORY_
{
    UINT pid;
    BYTE owner;
    UINT data;
} MEMORY, * PMEMORY;

UINT CreatePID()
{
    static UINT pid = 0;
    return pid++;
}

VOID * NativeMalloc(UINT size)
{
    VOID * tmp = malloc(size);
    memset(tmp, 0, size);
    return tmp;
}

VOID NativeFree(VOID * ptr)
{
    free(ptr);
}

UINT Random()
{
    static UINT X = 0;
    UINT A = 1664525, C = 1013904223, M = 2147483647;
    X = (X * A + C) & M;
    return X >> 16;
}

UINT RandomInstruction()
{
    return Random() % INSTRUCTION_NUMBER;
}

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

typedef struct Owner_
{
    CHAR name[MAX_PATH];
} Owner, * POwner;

typedef struct OwnerTable_
{
    UINT     size;
    POwner * data;
} OwnerTable, * POwnerTable;

typedef struct WORLD_
{
    UINT            size;
    PMEMORY         memory;
    PPROGRAM_QUEUE  pgmq;
    UINT            mutation_rate;
    UINT            iteration_number;
    OwnerTable      owntbl;
} WORLD, * PWORLD;

CONST PCHAR GetOwnerName(PWORLD wld, UINT owner)
{
    return wld->owntbl.data[owner - USER]->name;
}

PMEMORY GetMemory(PWORLD wld, UINT addr)
{
    return wld->memory + addr;
}

VOID InitMemory(PWORLD wld, UINT addr, UINT size)
{
    memset(GetMemory(wld, addr), 0, sizeof(MEMORY) * size);
}

VOID ReleaseOldestProgram(PWORLD wld, PPROGRAM_QUEUE pgmq)
{
    InitMemory(wld, pgmq->data[pgmq->cur].addr, pgmq->data[pgmq->cur].size);
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
            if (GetMemory(wld, i)->owner == SYSTEM)
            {
                tmp = 0;
                while (tmp < size && GetMemory(wld, i + tmp)->owner == SYSTEM)
                    ++tmp;
                if (tmp == size)
                {
                    InitMemory(wld, i, size);
                    return i;
                }
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

VOID InitProgram(PPROGRAM pgm, PWORLD wld, BYTE owner, PUINT data, UINT size)
{
    UINT i;

    pgm->owner = owner;
    pgm->pid = CreatePID();
    pgm->size = size;
    pgm->addr = MemoryAllocate(wld, size);
    for (i = 0; i < size; ++i)
    {
        GetMemory(wld, pgm->addr)->pid = pgm->pid;
        GetMemory(wld, pgm->addr)->data = data[i];
    }
    pgm->ptr = pgm->addr;
}

typedef struct WORLD_PARAM_
{
    UINT world_size;
    UINT program_number;
    UINT mutation_rate;
    UINT iteration_number;
} WORLD_PARAM, * PWORLD_PARAM;

PWORLD CreateWorld(PWORLD_PARAM param)
{
    PWORLD wld = (PWORLD)NativeMalloc(sizeof(WORLD));
    wld->size = param->world_size;
    wld->memory = (PMEMORY)NativeMalloc(param->world_size * sizeof(MEMORY));
    wld->pgmq = CreateProgramQueue(param->program_number);
    wld->mutation_rate = param->mutation_rate;
    wld->iteration_number = param->iteration_number;
    return wld;
}

VOID ReleaseWorld(PWORLD wld)
{
    if (wld)
    {
        NativeFree(wld->memory);
        ReleaseProgramQueue(wld->pgmq);
        NativeFree(wld);
    }
}

VOID WriteMemory(PWORLD wld, PPROGRAM pgm, UINT addr, UINT data)
{
    if (wld->size >= addr)
        return;
    if (pgm->owner == GetMemory(wld, addr)->owner)
        GetMemory(wld, addr)->data = data;
}

UINT ReadMemory(PWORLD wld, PPROGRAM pgm, UINT addr)
{
    if (wld->size >= addr)
        return NOP;
    return GetMemory(wld, addr)->data;
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

VOID NOP_(PWORLD wld, PPROGRAM pgm)
{
    IncreceProgramCounter(pgm, 1);
}

VOID NEXT_(PWORLD wld, PPROGRAM pgm)
{
    pgm->ptr += pgm->rgst;
    IncreceProgramCounter(pgm, 1);
}

VOID PREV_(PWORLD wld, PPROGRAM pgm)
{
    pgm->ptr -= pgm->rgst;
    IncreceProgramCounter(pgm, 1);
}

VOID ADD_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst += ReadMemory(wld, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID SUB_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst -= ReadMemory(wld, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID AND_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst &= ReadMemory(wld, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID OR_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst |= ReadMemory(wld, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID XOR_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst ^= ReadMemory(wld, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID NOT_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst = (pgm->rgst != 0) ? 0 : ~0;
    IncreceProgramCounter(pgm, 1);
}

VOID SLA_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst <<= ReadMemory(wld, pgm, pgm->ptr);
    pgm->rgst &= ~1;
    IncreceProgramCounter(pgm, 1);
}

VOID SRA_(PWORLD wld, PPROGRAM pgm)
{
    UINT msb;
    msb = ReadMemory(wld, pgm, pgm->ptr) & 0x80000000;
    pgm->rgst >>= ReadMemory(wld, pgm, pgm->ptr);
    pgm->rgst |= msb;
    IncreceProgramCounter(pgm, 1);
}

VOID SLL_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst <<= ReadMemory(wld, pgm, pgm->ptr);
    pgm->rgst &= 0x8FFFFFFF;
    IncreceProgramCounter(pgm, 1);
}

VOID SRL_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst >>= ReadMemory(wld, pgm, pgm->ptr);
    pgm->rgst &= ~1;
    IncreceProgramCounter(pgm, 1);
}

VOID READ_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst = ReadMemory(wld, pgm, pgm->ptr);
    IncreceProgramCounter(pgm, 1);
}

VOID WRITE_(PWORLD wld, PPROGRAM pgm)
{
    WriteMemory(wld, pgm, pgm->ptr, pgm->rgst);
    IncreceProgramCounter(pgm, 1);
}

VOID SAVE_(PWORLD wld, PPROGRAM pgm)
{
    pgm->tmp = pgm->rgst;
    IncreceProgramCounter(pgm, 1);
}

VOID SWAP_(PWORLD wld, PPROGRAM pgm)
{
    UINT tmp;
    tmp = pgm->tmp;
    pgm->tmp = pgm->rgst;
    pgm->rgst = tmp;
    IncreceProgramCounter(pgm, 1);
}

VOID SET_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst = ReadMemory(wld, pgm, pgm->pc + 1);
    IncreceProgramCounter(pgm, 2);
}

VOID JMP_(PWORLD wld, PPROGRAM pgm)
{
    pgm->pc = pgm->rgst;
    RoundProgramCounter(pgm);
}

VOID JEZ_(PWORLD wld, PPROGRAM pgm)
{
    if (pgm->tmp == 0)
        pgm->pc = pgm->rgst;
    RoundProgramCounter(pgm);
}

VOID PUSH_(PWORLD wld, PPROGRAM pgm)
{
    --pgm->sp;
    WriteMemory(wld, pgm, pgm->sp, pgm->rgst);
    IncreceProgramCounter(pgm, 1);
}

VOID POP_(PWORLD wld, PPROGRAM pgm)
{
    pgm->rgst = ReadMemory(wld, pgm, pgm->sp);
    ++pgm->sp;
    IncreceProgramCounter(pgm, 1);
}

VOID CALL_(PWORLD wld, PPROGRAM pgm)
{
    if (pgm->pc + 1 >= pgm->size)
        return;
    --pgm->sp;
    WriteMemory(wld, pgm, pgm->sp, pgm->pc + 2);
    pgm->pc = ReadMemory(wld, pgm, pgm->pc + 1);
}

VOID RET_(PWORLD wld, PPROGRAM pgm)
{
    pgm->pc = ReadMemory(wld, pgm, pgm->sp);
    ++pgm->sp;
    RoundProgramCounter(pgm);
}

VOID PREPARE_(PWORLD wld, PPROGRAM pgm)
{
    IncreceProgramCounter(pgm, 1);
}

VOID MALLOC_(PWORLD wld, PPROGRAM pgm)
{
    IncreceProgramCounter(pgm, 1);
}

typedef struct INSTRUCTION_INFO_
{
    CHAR             mnemonic[32];
    UINT             code;
    INSTRUCTION_IMPL impl;
} INSTRUCTION_INFO, * PINSTRUCTION_INFO;

#define DECLARE_INSTRUCTION_INFO(s) {STRING(s), s, s##_}
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
    DECLARE_INSTRUCTION_INFO(MALLOC ),
};
#undef DECLARE_INSTRUCTION_INFO

CONST PCHAR CodeToMnemonic(UINT code)
{
    return instruction_info_table[code].mnemonic;
}

UINT MnemonicToCode(CONST PCHAR mnemonic)
{
    UINT i;
    for (i = 0; i < sizeof(instruction_info_table) / sizeof(*instruction_info_table); ++i)
        if (stricmp(mnemonic, instruction_info_table[i].mnemonic) == 0)
            return instruction_info_table[i].code;
    return -1;
}

INSTRUCTION_IMPL CodeToImpl(UINT code)
{
    return instruction_info_table[code].impl;
}

#define TEMP_PAGE_SIZE 1024

typedef struct TEMP_PAGE_
{
    UINT data[TEMP_PAGE_SIZE];
    TEMP_PAGE_ * next;
} TEMP_PAGE, * PTEMP_PAGE;

typedef struct ASSEMBLY_
{
    UINT  size;
    PCHAR data;
} ASSEMBLY, * PASSEMBLY;

#define LINE_LENGTH_FORMAT 1024
#define LINE_LENGTH (LINE_LENGTH_FORMAT + 1)
PASSEMBLY CreateAssemblyFromFile(CONST PCHAR file)
{
    PASSEMBLY asm_;
    PTEMP_PAGE toppage, curpage, tmppage;
    FILE * fp;
    UINT pagepos, bufpos, code;
    CHAR mnemonic[LINE_LENGTH];

    fp = fopen(file, "rb");
    if (!fp)
        return NULL;

    asm_ = (PASSEMBLY)NativeMalloc(sizeof(PASSEMBLY));
    curpage = toppage = (PTEMP_PAGE)NativeMalloc(sizeof(PTEMP_PAGE));
    pagepos = 0;
    while (TRUE)
    {
        if (pagepos == TEMP_PAGE_SIZE)
        {
            curpage->next = (PTEMP_PAGE)NativeMalloc(sizeof(PTEMP_PAGE));
            curpage = curpage->next;
            pagepos = 0;
        }

        fscanf(fp, "%" STRING(LINE_LENGTH_FORMAT) "[a-zA-Z0-9]", mnemonic);

        code = MnemonicToCode(mnemonic);
        if (code != -1)
        {
            curpage->data[pagepos] = code;
        }

        ++pagepos;
        ++asm_->size;
    }

    asm_->data = (PCHAR)NativeMalloc(sizeof(CHAR) * asm_->size);
    curpage = toppage;
    bufpos = pagepos = 0;
    for (bufpos = 0; bufpos < asm_->size; ++bufpos)
    {
        if (pagepos == TEMP_PAGE_SIZE)
        {
            curpage = curpage->next;
            pagepos = 0;
        }
        asm_->data[bufpos] = curpage->data[pagepos];
        ++bufpos;
    }

    curpage = toppage;
    while (curpage)
    {
        tmppage = curpage->next;
        NativeFree(curpage);
        curpage = tmppage;
    }

    fclose(fp);

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

VOID Step(PWORLD wld, PPROGRAM pgm)
{
    UINT code;
    code = GetMemory(wld, pgm->pc)->data;
    if (code < INSTRUCTION_NUMBER)
        CodeToImpl(code)(wld, pgm);
}

VOID Tick(PWORLD wld)
{
    UINT i;
    for (i = 0; i < wld->pgmq->size; ++i)
    {
        if (wld->pgmq->data[i].owner != SYSTEM)
        {
            Step(wld, &wld->pgmq->data[i]);
        }
    }
}

typedef struct SCORE_WONER_PAIR_
{
    UINT score;
    UINT owner;
} SCORE_WONER_PAIR, * PSCORE_WONER_PAIR;

int ScoreWonerPairComparator(CONST VOID * a, CONST VOID * b)
{
    return ((PSCORE_WONER_PAIR)b)->score - ((PSCORE_WONER_PAIR)a)->score;
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

CONST CHAR * SuffixString(UINT n)
{
    if (n == 1)
        return "st";
    if (n == 2)
        return "nd";
    return "th";
}

VOID Judge(PWORLD wld)
{
    UINT i;
    PSCORE_WONER_PAIR pairs;
    
    pairs = (SCORE_WONER_PAIR *)NativeMalloc(wld->owntbl.size * sizeof(SCORE_WONER_PAIR));

    for (i = 0; i < wld->owntbl.size; ++i)
        pairs[i].owner = i + USER;

    for (i = 0; i < wld->pgmq->size; ++i)
        ++pairs[wld->pgmq->data[i].owner - USER].score;

    qsort(pairs, wld->owntbl.size, sizeof(SCORE_WONER_PAIR), ScoreWonerPairComparator);

    for (i = 0; i < wld->owntbl.size; ++i)
        printf("%d%s %s (%d)\n", i + 1, SuffixString(i + 1), GetOwnerName(wld, pairs[i].owner), pairs[i].score);

    NativeFree(pairs);
}

VOID Run(PWORLD wld)
{
    UINT i;
    for (i = 0; i < wld->iteration_number; ++i)
        Tick(wld);
}

int main(int argc, const char ** argv)
{
    PWORLD wld;

    WORLD_PARAM param = {
        1000 * 1000 * 100,
        1000,
        1000 * 1000 * 1000 * 10
    };

    wld = CreateWorld(&param);

    Run(wld);
    Judge(wld);

    ReleaseWorld(wld);
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
基本的にインクリメントやデクリメントを繰り返すことで複雑な処理を記述する。

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

*/