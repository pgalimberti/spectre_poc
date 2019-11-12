#ifndef SPECTRE_ATTACK_H
#define SPECT
#include "ui_mainwindow.h"

#include <iostream>
#include <emmintrin.h> //libreria che serve a eseguire il flush della cache : _mm_clflush(..)
#include <QString>

#include <x86intrin.h>
//librerie utili per il leak del kernel ( utilizzo di pread e open)
#include <unistd.h>
#include <fcntl.h>

#define BRANCH_PREDICTOR_TRAIN    6
#define BYTE_VALUES     256
#define PAGE_SIZE       4096  /* x86 default 4K */
#define CACHE_HIT_THRESHOLD 80 //soglia di un cache hit

#define LINUX_PROC_BANNER 0xffffffff81e00060 //Kernel info

class spectre_attack
{
public:
    size_t array_size = BRANCH_PREDICTOR_TRAIN;
    uint8_t array[BRANCH_PREDICTOR_TRAIN];
    //inizializzo con un valore "junk" per la lettura in cache
    uint8_t effetto_collaterale[BYTE_VALUES * PAGE_SIZE] = {1};
    //variabile che serve ad impedire l'intervento dell'ottimizzazione
    uint8_t mem_in_cache;
    /*intero che rappresenta un file in Linux sul quale si posson ofare operazioni di input/output.
     di fatto si tratta di un indice di un array del process control block
     che ha riferimenti a strutture dati del kernel*/
    int file_descriptor; //kernel leak

    uint8_t vittima(uint64_t x);
    uint8_t read(uint64_t addr, bool flag_leak_kernel);
    void attack(QTextBrowser* text,QString stringa, bool flag_kernel);
};

#endif // SPECTRE_ATTACK_H
