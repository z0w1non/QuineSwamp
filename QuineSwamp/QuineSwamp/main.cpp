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

���̃Q�[���ł́A�����̃v���C���[���������Ƀv���O������z�u�����ȕ���������B
�ŏI�I�ɂ�葽���̃������������̃v���O�����Ŗ��ߐs�������v���C���[�����҂ƂȂ�B

�������̊e�Ԓn�ɂ́A���߃Z�b�g�Ɋ܂܂�邢���ꂩ�̒l���i�[�����B
�e�v���C���[�����삵���v���O�����́A�����_���ɑI�����ꂽ�������ɘA�����Ĕz�u�����B

�v���O�����͈ȉ��̗v�f����\�������B

    �v���O�����J�E���^
    �|�C���^
    ���W�X�^
    �e���|�������W�X�^
    �X�^�b�N�|�C���^

�v���O�����̃R�[�h���������ɔz�u�����Ƃ��A
�v���O�����J�E���^�ƃ|�C���^�͔z�u���ꂽ�R�[�h�̐擪�̃A�h���X�ɐݒ肳��A
�X�^�b�N�|�C���^�͔z�u���ꂽ�R�[�h�̖����̃A�h���X�ɐݒ肳���B
�v���O�����̃R�[�h�����s����邽�сA�v���O�����J�E���^�͂ЂƂC���N�������g�����B(JMP, JEZ������)
�v���O�����J�E���^���v���O�����̃R�[�h�͈̔͂𒴂����ꍇ�A�v���O�����J�E���^�͔z�u���ꂽ�R�[�h�̐擪���w���悤�ݒ肳���B

���߃Z�b�g�� brainf*ck ���Q�l�ɐ݌v����Ă���B
��{�I�ɃC���N�������g��f�N�������g���J��Ԃ����Ƃŕ��G�ȏ������L�q����B

    NOP    : �����s��Ȃ��B
    NEXT   : �|�C���^���w���������̃A�h���X�Ƀ��W�X�^�̒l�����Z����B
    PREV   : �|�C���^���w���������̃A�h���X�Ƀ��W�X�^�̒l�����Z����B
    ADD    : ���W�X�^�̒l�Ƀ|�C���^���w���������̒l�����Z����B
    SUB    : ���W�X�^�̒l�Ƀ|�C���^���w���������̒l�����Z����B
    AND    : ���W�X�^�̒l�Ƀ|�C���^���w���������̒l��AND���Z����B
    OR     : ���W�X�^�̒l�Ƀ|�C���^���w���������̒l��OR���Z����B
    XOR    : ���W�X�^�̒l�Ƀ|�C���^���w���������̒l��XOR���Z����B
    NOT    : ���W�X�^�̒l�� 0 �̏ꍇ�A���W�X�^�̒l��S�r�b�g1�ɐݒ肷��B���W�X�^�̒l�� 1 �̏ꍇ�A���W�X�^�̒l��S�r�b�g0�ɐݒ肷��B
    SLA    : ���W�X�^�̒l���|�C���^���w���������̒l�ŎZ�p���V�t�g���Z����B
    SRA    : ���W�X�^�̒l���|�C���^���w���������̒l�ŎZ�p�E�V�t�g���Z����B
    SLL    : ���W�X�^�̒l���|�C���^���w���������̒l�Ř_�����V�t�g���Z����B
    SRL    : ���W�X�^�̒l���|�C���^���w���������̒l�Ř_���E�V�t�g���Z����B
    READ   : ���W�X�^�̒l���|�C���^���w���������̒l�ɕύX����B
    WRITE  : �|�C���^���w���������̒l�����W�X�^�̒l�ɕύX����B
    SAVE   : �e���|�������W�X�^�̒l�����W�X�^�̒l�ɕύX����B
    SWAP   : ���W�X�^�̒l�ƃe���|�������W�X�^�̒l����������B
    SET    : ���W�X�^��萔�ɕύX����B
    JMP    : �v���O�����J�E���^�����W�X�^�̒l�ɕύX����B
    JEZ    : �e���|�������W�X�^�̒l�� 0 �ł���ꍇ�A�v���O�����J�E���^�����W�X�^�̒l�ɕύX����B
    PUSH   : �X�^�b�N�|�C���^�� 1 ���Z���A���W�X�^�̒l���X�^�b�N�|�C���^���w���������̒l�ɕύX����B
    POP    : ���W�X�^�̒l���X�^�b�N�|�C���^���w���������̒l�ɕύX���A�X�^�b�N�|�C���^�� 1 ���Z����B
    CALL   : �X�^�b�N�|�C���^�� 1 ���Z���A�X�^�b�N�|�C���^���w���������̒l���A�v���O�����J�E���^�̒l�� 2 �����Z�����A�h���X�ɕύX����B
    RET    : �v���O�����J�E���^�̒l���X�^�b�N�|�C���^���w���������̒l�ɕύX���A�X�^�b�N�|�C���g�� 1 ���Z����B
    PREPARE: ���� MALLOC �����s�����ۂɊ��蓖�Ă��郁�����̑傫�����C���N�������g����B
    MALLOC : �O�� MALLOC ���Ăяo����Ă��猻�݂܂ł� PREPARE �����s���ꂽ�񐔕��̑傫���̃��������m�ۂ���B
             ���W�X�^�̒l���m�ۂ��ꂽ�������̐擪�̃A�h���X�ɕύX����B
             �X�^�b�N�|�C���^�̒l���m�ۂ��ꂽ�������̖����ɕύX����B

�������̓ǂݏ����ɂ͐���������B
�������ɔz�u���ꂽ�v���O�����́A���g�̏��L�҈ȊO�ɂ�菊�L����Ă���v���O�������z�u���ꂽ�������ɏ������ނ��Ƃ��ł����A�ǂݍ��ނ��Ƃ������ł���B
����ȊO�̃������ɑ΂��ẮA�ǂݍ��݂Ə������݂̗������ł���B
�������̓ǂݏ����̌����ɂ��Ĉȉ��ɋL�ڂ���B

    �ERW ���g�̏��L�҂ɂ�菊�L�����v���O�������z�u���ꂽ������
    �ER- ���g�̏��L�҈ȊO�ɂ�菊�L����Ă���v���O�������z�u���ꂽ������
    �ERW ������̃v���O�������z�u����Ă��Ȃ�������

�����ŁA�v���O�������g���z�u���ꂽ�������́A�v���O�������g�̏������݂ɂ��ύX���邱�Ƃ��ł��邱�Ƃɒ��ӂ���B
�u�������ɔz�u���ꂽ�v���O�������v�Z�̂��ߎg�p�ł��郁�����v�Ɓu�������ɔz�u���ꂽ�v���O�������g�̃R�[�h�v�̊Ԃɂ͋�ʂ��Ȃ��B
��������΁A�v���O�����͎��s���Ɏ��Ȃ�ύX���邱�Ƃ��ł���B
�����̎d�l����A�ʏ�̃v���O�����̐݌v�ɂ����ẮA�v�Z�̂��߂Ɏg�p���郁�����̈���A�v���O�����̃R�[�h�̈�Ɋ܂߂�K�v�����邾�낤�B

���̃Q�[���́A����̉񐔂����e�B�b�N���J��Ԃ���邱�Ƃɂ����s�����B
1�e�B�b�N�̊ԂɁA�������ɔz�u���ꂽ�S�Ẵv���O�����͕����1���߂����s�����B
���ȕ����̏����𕡐��̃v���O�����ɂ�蕪�S���Ď��s���邱�Ƃ��ł���΁A���ȕ����̑��x�����コ���邱�Ƃ��ł���B

�Q�[�����i�s����ƁA������̃������ɂ��v���O�������z�u����A���̂܂܂ł͐V�����v���O������z�u���邱�Ƃ��s�\�ɂȂ�B
���̂��߁A�v���O���������ȕ��������݂�ۂɋ󂫃��������s�����Ă����ꍇ�A�V�X�e���͍ł��Â��ɔz�u���ꂽ�v���O������j������B
���̔j���͋󂫃������̕s�������������܂ŌJ��Ԃ����B
�j�����ꂽ�v���O�����͎��s����Ȃ��Ȃ邪�A�������ɔz�u���ꂽ�R�[�h�͂��̂܂܎c��B

���̃Q�[���͊��S�ȍČ�����L����B
���������̕����͌��J����A�ύX����Ȃ��B
�v���O���������ȕ�������ۂɓˑR�ψق͔������Ȃ��B

*/