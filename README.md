# 概要
このゲームでは、複数のプレイヤーがメモリにプログラムを配置し自己複製させる。
最終的により多くのメモリを自分のプログラムで埋め尽くしたプレイヤーが勝者となる。

## ルール
メモリの各番地には値が格納される。
命令セットの値は1バイトで表現され、定数は4バイトで表現される。
各プレイヤーが自作したプログラムは、ランダムに選択されたメモリに連続して配置される。

プロセッサは以下の要素から構成される。

| 名前               | 別名(ログ内で使用される) |
| ------------------ | ------------------------ |
| プログラムカウンタ | PC                       |
| ポインタ           | PTR                      |
| レジスタ           | ACC                      |
| テンポラリレジスタ | TMP                      |
| スタックポインタ   | SP                       |

プログラムがメモリに配置されるとき、配置されたプログラムにプロセッサが割り当てられる。
プロセッサのプログラムカウンタとポインタは配置されたコードの先頭のアドレスに設定され、
スタックポインタは配置されたコードの末尾のアドレスに設定される。
プロセッサによりプログラムが実行されるたび、プログラムカウンタはひとつインクリメントされる。(JMP, JEZを除く)
プログラムカウンタが配置されたプログラムの範囲を超えた場合、プログラムカウンタは配置されたプログラムの先頭のアドレスに変更される。


プロセッサの計算において値がアドレスとして解釈される場合、
そのアドレスはプロセッサが割り当てられているメモリに配置されたプログラムの先頭のアドレスを基準とした相対アドレスとして解釈される。
プログラムカウンタが指すメモリの値が命令セットのいずれの値にも合致しない場合、そのメモリの値を NOP として解釈する。

メモリの読み書きには制限がある。
プログラムに割り当てられたプロセッサは、自身の所有者以外により所有されているプログラムが配置されたメモリに書き込むことができず、読み込むことだけができる。
それ以外のメモリに対しては、読み込みと書き込みの両方ができる。
書き込み権限のないメモリに対して書き込みを試行した場合、あるいは読み込み権限のないメモリに対して読み込みを施行した場合、何も起きない。
メモリの読み書きの権限について以下に記載する。

| 読み込み権限 | 書き込み権限 | メモリの分類                                                     |
| ------------ | ------------ | ---------------------------------------------------------------- |
| o            | o            | 自身の所有者により所有されるプログラムが配置されたメモリ         |
| o            | x            | 自身の所有者以外により所有されているプログラムが配置されたメモリ |
| o            | o            | いずれのプログラムも配置されていないメモリ                       |

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

## 命令セット
命令セットは brainf*ck を参考に設計されている。

| ニーモニック | 説明                                                                                                                        |
| ------------ | --------------------------------------------------------------------------------------------------------------------------- |
| NOP          | 何も行わない。                                                                                                              |
| SEEK         | ポインタが指すメモリのアドレスをレジスタの値に変更する。                                                                    |
| ADD          | レジスタの値にテンポラリレジスタの値を加算し、レジスタの値をその結果に変更する。                                            |
| SUB          | レジスタの値からテンポラリレジスタの値を減算し、レジスタの値をその結果に変更する。                                          |
| AND          | レジスタの値とテンポラリレジスタの値でAND演算し、レジスタの値をその結果に変更する。                                         |
| OR           | レジスタの値とテンポラリレジスタの値でOR演算し、レジスタの値をその結果に変更する。                                          |
| XOR          | レジスタの値とテンポラリレジスタの値でXOR演算し、レジスタの値をその結果に変更する。                                         |
| NOT          | レジスタの値が 0 の場合、レジスタの値を全ビット1に設定する。レジスタの値が 1 の場合、レジスタの値を全ビット0に設定する。    |
| SLA          | テンポラリレジスタの値をレジスタの値で算術左シフト演算し、レジスタの値をその結果に変更する。                                |
| SRA          | テンポラリレジスタの値をレジスタの値で算術右シフト演算し、レジスタの値をその結果に変更する。                                |
| SLL          | テンポラリレジスタの値をレジスタの値で論理左シフト演算し、レジスタの値をその結果に変更する。                                |
| SRL          | テンポラリレジスタの値をレジスタの値で論理右シフト演算し、レジスタの値をその結果に変更する。                                |
| READ         | レジスタの値をポインタが指すメモリの値(4バイト)に変更する。                                                                 |
| WRITE        | ポインタが指すメモリの値(4バイト)をレジスタの値に変更する。                                                                 |
| SAVE         | テンポラリレジスタの値をレジスタの値に変更する。                                                                            |
| SWAP         | レジスタの値とテンポラリレジスタの値を交換する。                                                                            |
| SET          | レジスタを定数(直後の4バイト)に変更する。                                                                                   |
| JMP          | プログラムカウンタをレジスタの値に変更する。                                                                                |
| JEZ          | テンポラリレジスタの値が 0 である場合、プログラムカウンタをレジスタの値に変更する。                                         |
| PUSH         | スタックポインタを 1 減算し、スタックポインタが指すメモリの値をレジスタの値に変更する。                                     |
| POP          | レジスタの値をスタックポインタが指すメモリの値に変更し、スタックポインタを 1 加算する。                                     |
| CALL         | スタックポインタを 1 減算し、スタックポインタが指すメモリの値を、プログラムカウンタの値に 2 を加算したアドレスに変更する。  |
| RET          | プログラムカウンタの値をスタックポインタが指すメモリの値に変更し、スタックポイントを 1 加算する。                           |
| RESERVE      | ポインタが指すメモリの値(1バイト)を、次回 MALLOC を実行したときにメモリに配置されるプログラムの末尾に追加する。             |
| MALLOC       | RESERVE により蓄積されたデータを割り当てられたメモリに配置し、プロセッサを割り当てる。                                      |
| ADDR         | レジスタの値をプロセッサが割り当てられているメモリの先頭の絶対アドレスに変更する。                                          |
| SIZE         | レジスタの値をプロセッサが割り当てられているメモリのサイズに変更する。                                                      |

### スタック
スタックポインタは配置されたコードの末尾のアドレスに設定される。
PUSH, POP, CALL, RET等の命令は、プログラムの末尾から先頭に向かうメモリをスタックとして利用する。
そのため、プログラムが動作するために必要な実行コードがプログラムの末尾に配置されている場合、これらの命令はいずれもプログラムの挙動に対して破壊的な効果を与える。
したがって、通常PUSH, POP, CALL, RET等の命令によりスタックを利用するプログラムは、自身の実行コードの末尾にスタック用のメモリ領域を NOP 等により確保する。

### 自己複製の主な流れ
* プログラムの先頭から末尾までのアドレスを PTR に設定し、それぞれの値で RESERVE 命令を実行する。
* MALLOC 命令を実行する。

## アセンブリ
アセンブリは以下のフォーマットで記述する。

```
SET MYLABEL
JMP
HOGE:
0
FUGA:
0xFF00
MYLABEL:
0x12345678
```

ニーモニックを複数行に記述する。
改行や空白を複数連続させてもアセンブルの結果には影響しないため、可読性の都合により任意にインデントを調整したり、改行を省略しても問題ない。

定数は4バイトの数値として解釈される。
数値に0xを前置すると16進数として解釈される。

:を後置すると、ラベルの宣言として解釈される。
ラベルは宣言されるより以前に使用することができる。
ラベルの名前は [a-zA-Z_][a-zA-Z0-9_]* でなければならない。
ソースに含まれるラベルは、ラベルが宣言された場所の4バイトのアドレスに展開される。
