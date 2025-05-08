#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
//m3 include
#include <time.h>
//CONVERSIONS DONT TOUCH
#define KILOBYTE 1024
#define MEGABYTE (1024 * KILOBYTE)
#define PAGE_OFFSET_SIZE (4 * KILOBYTE)
#define PAGE_TABLE_ENTRIES (512 * KILOBYTE)
#define MAX_TRACE_FILES 3

//M3 structs for vm and cache
typedef struct {
    unsigned int tag;
    int valid;
} cache_line;

typedef struct {
    unsigned int phys_page;
    int valid;
} page_table_entry;


//  CPI calc
#define ACCESS_IFETCH 0
#define ACCESS_READ   1
#define ACCESS_WRITE  2

// confi in init_simulation
static cache_line **cache_sets;
static page_table_entry *page_tables[MAX_TRACE_FILES];
static int    num_sets, block_bytes, associativity;
static int    num_physical_pages;
static int   *free_physical;
static long   instructions_per_slice;
//m3 cpi fix !
static unsigned long inst_count;

// stats
static unsigned long total_cache_accesses, inst_bytes, data_bytes;
static unsigned long cache_hits, cache_misses,
                   compulsory_misses, conflict_misses;
static unsigned long page_table_hits, page_table_from_free, page_faults;
static unsigned long total_cycles;

//STRUCTS
typedef struct cache_input_parameters {
    int cache_size;
    int block_size;
    int associativity;
    int physical_memory;

    long instructions;
    double percent_memory;

    char *replacement_policy;
    char **trace_files;
} cache_ip;



typedef struct cache_calculated_values {
    int total_blocks;
    int tag_size;
    int index_size;
    int block_offset_size;
    int total_rows;
    int overhead_size;
    int memory_size;

    double cost;
} cache_cv;

//m3 ouput FIX ME 5/4/25

typedef struct physical_memory_calculated_values {
    int total_physical_pages;
    int total_system_pages;
    int page_table_entry_size;
    int total_RAM_page_tables;
} physical_memory_cv;

//m3 prototypes
void init_simulation(cache_ip *ip, cache_cv *cv);
unsigned int translate_address(int pid, unsigned int vaddr);
void cache_access(unsigned int paddr, int access_type, int bytes);
void simulate_trace(int pid, const char *filename);
void print_cache_simulation_results(cache_cv *cv);

//ouput fix
void print_vm_results(cache_ip *ip, int ntraces);
void print_page_table_usage(char *trace_files[], int ntraces);



//PROTOTYPES DONT TOUCH
void free_trace_files(cache_ip *input_parameters);
void specify_cache_size(char *input, cache_ip *ip);
void specify_block_size(char *input, cache_ip *ip);
void specify_associativity(char *input, cache_ip *ip);
void specify_replacement_policy(char *input, cache_ip *ip);
void specify_physical_memory(char *input, cache_ip *ip);
void specify_percent_memory(char *input, cache_ip *ip);
void specify_instructions(char *input, cache_ip *ip);

void calculate_total_blocks(cache_ip *ip, cache_cv *cv);
void calculate_tag_size(cache_ip *ip, cache_cv *cv);
void calculate_index_size(cache_cv *cv);
void calculate_total_rows(cache_ip *ip, cache_cv *cv);
void calculate_overhead_size(cache_cv *cv);
void calculate_memory_size(cache_ip *ip, cache_cv *cv);
void calculate_cost(cache_cv *cv);
void calculate_total_physical_pages(cache_ip *ip, physical_memory_cv *cv);
void calculate_total_system_pages(cache_ip *ip, physical_memory_cv *cv);
void calculate_page_table_entry_size(physical_memory_cv *cv);
void calculate_total_RAM_page_tables(physical_memory_cv *cv, int counter);

void display_trace_files(cache_ip *ip, int counter);
void display_cache_input_parameters(cache_ip *ip);
void display_cache_calculated_values(cache_cv *cv);
void display_physical_memory_calculated_values(physical_memory_cv *cv);


void free_trace_files(cache_ip *input_parameters) {
    free(input_parameters->trace_files);
}

void specify_cache_size(char *input, cache_ip *ip) {
    int conversion = atoi(input);

    if((conversion < 8) || (conversion > 16384) || ((conversion & (conversion - 1)) != 0)) {
        printf("\t- [ERROR]: Invalid cache size specification.\n");
        free_trace_files(ip);
        exit(1);
    }

    ip->cache_size = conversion;
}

void specify_block_size(char *input, cache_ip *ip) {
    int conversion = atoi(input);

    if((conversion < 8) || (conversion > 64) || ((conversion & (conversion - 1)) != 0)) {
        printf("\t- [ERROR]: Invalid block size specification.\n");
        free_trace_files(ip);
        exit(1);
    }

    ip->block_size = conversion;
}

void specify_associativity(char *input, cache_ip *ip) {
    int conversion = atoi(input);

    if((conversion < 1) || (conversion > 16) || ((conversion & (conversion - 1)) != 0)) {
        printf("\t- [ERROR]: Invalid associativity specification.\n");
        free_trace_files(ip);
        exit(1);
    }

    ip->associativity = conversion;
}

void specify_replacement_policy(char *input, cache_ip *ip) {
    int index = 0;

    for(index = 0; input[index] != '\0'; index++) {
        input[index] = toupper(input[index]);
    }

    if(strcmp(input, "RR") == 0) {
        ip->replacement_policy = "Round Robin";
    }
    else if(strcmp(input, "RND") == 0) {
        ip->replacement_policy = "Random";
    }
    else {
        printf("\t- [ERROR]: Invalid replacement policy specification.\n");
        free_trace_files(ip);
        exit(1);
    }
}

void specify_physical_memory(char *input, cache_ip *ip) {
    int conversion = atoi(input);

    if((conversion < 128) || (conversion > 4096) || ((conversion & (conversion - 1)) != 0)) {
        printf("\t- [ERROR]: Invalid physical memory specification.\n");
        free_trace_files(ip);
        exit(1);
    }

    ip->physical_memory = conversion;
}

void specify_percent_memory(char *input, cache_ip *ip) {
    double conversion = atof(input);

    if((conversion < 0.0) || (conversion > 100.0)) {
        printf("\t- [ERROR]: Invalid percentage of physical memory used by the ");
        printf("operating system specification.\n");
        free_trace_files(ip);
        exit(1);
    }

    ip->percent_memory = conversion;
}

void specify_instructions(char *input, cache_ip *ip) {
    long conversion = atol(input);
    
    if(((conversion < 1) && (conversion != -1)) || (conversion > 0xFFFFFFFF)) {
        printf("\t- [ERROR]: Invalid instructions per time splice ");
        printf("specification.\n");
        free_trace_files(ip);
        exit(1);
    }

    ip->instructions = conversion;
}

void calculate_total_blocks(cache_ip *ip, cache_cv *cv) {
    cv->total_blocks = ((ip->cache_size * KILOBYTE) / ip->block_size);
}

void calculate_tag_size(cache_ip *ip, cache_cv *cv) {
    cv->block_offset_size = __builtin_ctz(ip->block_size);

  
    uint64_t phys_bytes = (uint64_t)(ip->physical_memory) * MEGABYTE;
    int phys_addr_bits = 0;
    while ((1ULL << phys_addr_bits) < phys_bytes) {
        phys_addr_bits++;
    }

    int used_bits = cv->index_size + cv->block_offset_size;

  
    if (used_bits >= phys_addr_bits) {
        fprintf(stderr,
                "- [ERROR]: index_size (%d) + offset_size (%d) = %d\n"
                "  exceeds physical-address width (%d bits).\n",
                cv->index_size, cv->block_offset_size,
                used_bits, phys_addr_bits);
        exit(1);
    }

    //LEFTOVERS FIX ME
    cv->tag_size = phys_addr_bits - used_bits;
}

void calculate_index_size(cache_cv *cv) {
    cv->index_size = log2(cv->total_rows);
}

void calculate_total_rows(cache_ip *ip, cache_cv *cv) {
    cv->total_rows = (cv->total_blocks / ip->associativity); 
}

void calculate_overhead_size(cache_cv *cv) {
    cv->overhead_size = (((cv->tag_size + 1) * cv->total_blocks) / 8);
}

void calculate_memory_size(cache_ip *ip, cache_cv *cv) {
    cv->memory_size = ((ip->cache_size * KILOBYTE) + cv->overhead_size);
}

void calculate_cost(cache_cv *cv) {
    cv->cost = ((cv->memory_size * 0.12) / KILOBYTE);
}

void calculate_total_physical_pages(cache_ip *ip, physical_memory_cv *cv) {
    cv->total_physical_pages = ((ip->physical_memory * MEGABYTE) / 
        PAGE_OFFSET_SIZE);
}

void calculate_total_system_pages(cache_ip *ip, physical_memory_cv *cv) {
    cv->total_system_pages = ((ip->percent_memory / 100) * 
        cv->total_physical_pages); 
}

void calculate_page_table_entry_size(physical_memory_cv *cv) {
    cv->page_table_entry_size = (log2(cv->total_physical_pages) + 1);
}

void calculate_total_RAM_page_tables(physical_memory_cv *cv, int counter) {
    cv->total_RAM_page_tables = (((PAGE_TABLE_ENTRIES * counter) * 
        cv->page_table_entry_size) / 8);
}

void display_trace_files(cache_ip *ip, int counter) {
    printf("Trace File(s):\n");
    int index = 0;

    for(index = 0; index < counter; index++) {
        printf("%8s%s\n", "", ip->trace_files[index]);
    }

    printf("\n");
}

void display_cache_input_parameters(cache_ip *ip) {
    printf("***** Cache Input Parameters *****\n\n");
    printf("%-32s%d KB\n", "Cache Size:", ip->cache_size);
    printf("%-32s%d bytes\n", "Block Size:", ip->block_size);
    printf("%-32s%d\n", "Associativity:", ip->associativity);
    printf("%-32s%s\n", "Replacement Policy:", ip->replacement_policy);
    printf("%-32s%d MB\n", "Physical Memory:", ip->physical_memory);
    printf("%-32s%.1lf%%\n", "Percent Memory Used by System:", ip->percent_memory);
    printf("%-32s%ld\n\n", "Instructions / Time Slice:", ip->instructions);
}

void display_cache_calculated_values(cache_cv *cv) {
    printf("***** Cache Calculated Values *****\n\n"); 
    printf("%-32s%d\n", "Total # Blocks:", cv->total_blocks);
    printf("%-32s%d bits\n", "Tag Size:", cv->tag_size);
    printf("%-32s%d bits\n", "Index Size:", cv->index_size);
    printf("%-32s%d\n", "Total # Rows:", cv->total_rows);
    printf("%-32s%d bytes\n", "Overhead Size:", cv->overhead_size);
    printf("%-32s%.2lf KB  (%d bytes)\n", "Implementation Memory Size:", 
        (cv->memory_size / (double) KILOBYTE), cv->memory_size);
    printf("%-32s$%.2lf @ $0.12 per KB\n\n", "Cost:", cv->cost);
}

void display_physical_memory_calculated_values(physical_memory_cv *cv) {
    printf("***** Physical Memory Calculated Values *****\n\n");
    printf("%-32s%d\n", "Number of Physical Pages:", cv->total_physical_pages);
    printf("%-32s%d\n", "Number of Pages for System:", cv->total_system_pages);
    printf("%-32s%d bits\n", "Size of Page Table Entry:", 
        cv->page_table_entry_size);
    printf("%-32s%d bytes\n\n", "Total RAM for Page Table(s):", 
        cv->total_RAM_page_tables);
}

//m3 func TEMP NEED FIX 5/3/25
void init_simulation(cache_ip *ip, cache_cv *cv) {
    block_bytes = ip->block_size;
    associativity = ip->associativity;
    num_sets = cv->total_rows;
    instructions_per_slice = ip->instructions;

    // alloc cache
    cache_sets = malloc(num_sets * sizeof(cache_line*));
    for(int i=0;i<num_sets;i++){
        cache_sets[i] = calloc(associativity, sizeof(cache_line));
    }

   
    for(int p=0;p<MAX_TRACE_FILES;p++){
        page_tables[p] = calloc(PAGE_TABLE_ENTRIES, sizeof(page_table_entry));
    }

   
    num_physical_pages = (ip->physical_memory * MEGABYTE) / PAGE_OFFSET_SIZE;
    free_physical = malloc(num_physical_pages * sizeof(int));
    for(int i=0;i<num_physical_pages;i++) free_physical[i]=1;

    
    total_cache_accesses = inst_bytes = data_bytes = 0;
    cache_hits = cache_misses = compulsory_misses = conflict_misses = 0;
    page_table_hits = page_table_from_free = page_faults = 0;
    total_cycles = 0;
}

unsigned int translate_address(int pid, unsigned int vaddr) {
    unsigned int vpn    = vaddr / PAGE_OFFSET_SIZE;
    unsigned int offset = vaddr % PAGE_OFFSET_SIZE;
    page_table_entry *pt = page_tables[pid];

    if (pt[vpn].valid) {
        page_table_hits++;
    } else {
        int ppn = -1;
        // find free phys page
        for(int i=0;i<num_physical_pages;i++){
            if (free_physical[i]) { ppn = i; free_physical[i]=0; break; }
        }
        if (ppn >= 0) {
            page_table_from_free++;
        } else {
            // no free page → page fault + simple RANDOM replacement
               page_faults++;
               total_cycles += 100;   // penalty for a page fault :contentReference[oaicite:2]{index=2}:contentReference[oaicite:3]{index=3}
               ppn = rand() % num_physical_pages;

            // inv cache lines on page
            unsigned int base = ppn * PAGE_OFFSET_SIZE;
            for (unsigned int A = base; A < base + PAGE_OFFSET_SIZE; A += block_bytes) {
                unsigned int blk = A / block_bytes;
                unsigned int idx = blk % num_sets;
                unsigned int tag = blk / num_sets;
                for(int w=0; w<associativity; w++){
                    if (cache_sets[idx][w].valid && cache_sets[idx][w].tag == tag)
                        cache_sets[idx][w].valid = 0;
                }
            }
        }
        pt[vpn].phys_page = ppn;
        pt[vpn].valid     = 1;
    }
    return (pt[vpn].phys_page * PAGE_OFFSET_SIZE) + offset;
}

void cache_access(unsigned int paddr, int access_type, int bytes) {
    unsigned int first = paddr;
    unsigned int last  = paddr + bytes - 1;
    unsigned int fb = first / block_bytes, lb = last / block_bytes;

    for(unsigned int blk = fb; blk <= lb; blk++) {
        total_cache_accesses++;
        unsigned int idx = blk % num_sets;
        unsigned int tag = blk / num_sets;
        int hit = 0;
        for(int w=0; w<associativity; w++){
            if (cache_sets[idx][w].valid && cache_sets[idx][w].tag == tag) {
                hit = 1; break;
            }
        }
        if (hit) {
            cache_hits++;
            total_cycles += 1;        
        } else {
            cache_misses++;
            // class miss
            int empty_way = -1;
            for(int w=0; w<associativity; w++){
                if (!cache_sets[idx][w].valid) { empty_way = w; break; }
            }
            if (empty_way >= 0) compulsory_misses++;
            else conflict_misses++;
            
            int way = (empty_way>=0)? empty_way : (rand()%associativity);
            cache_sets[idx][way].valid = 1;
            cache_sets[idx][way].tag   = tag;
            
            int mem_reads = (block_bytes + 3) / 4;      // CEILING
            total_cycles += mem_reads * 4;
        }
        
        if (access_type == ACCESS_IFETCH)      total_cycles += 2;
        else if (access_type == ACCESS_READ ||
                 access_type == ACCESS_WRITE) total_cycles += 1;
    }
    if (access_type == ACCESS_IFETCH) inst_bytes += bytes;
    else                              data_bytes += bytes;
}

void simulate_trace(int pid, const char *fname) {
    FILE *fp = fopen(fname, "r");
    char line1[256], line2[256];
    while (fgets(line1, sizeof line1, fp) && fgets(line2, sizeof line2, fp)) {
        // parse ins
        int len; unsigned int vaddr;
        sscanf(line1, "EIP (%x): %x", &len, &vaddr);
      
        //m3 cpi fix
        inst_count++;
        unsigned int p = translate_address(pid, vaddr);
      
        cache_access(p, ACCESS_IFETCH, len);

        // parse data
        char dst[9], src[9];
        sscanf(line2, "dstM: %8s %*s srcM: %8s", dst, src);
        if (strcmp(dst, "00000000")) {
            unsigned int da = strtoul(dst, NULL, 16);
            p = translate_address(pid, da);
            cache_access(p, ACCESS_WRITE, 4);
        }
        if (strcmp(src, "00000000")) {
            unsigned int sa = strtoul(src, NULL, 16);
            p = translate_address(pid, sa);
            cache_access(p, ACCESS_READ, 4);
        }
    }
    fclose(fp);
}
//m3 ouput fix
void print_vm_results(cache_ip *ip, int ntraces) {
    (void)ntraces;
    unsigned long total_pages = ((unsigned long)ip->physical_memory * MEGABYTE)
                            / PAGE_OFFSET_SIZE;
    unsigned long sys_pages   = (unsigned long)(ip->percent_memory * 0.01
                            * total_pages + 0.5);
    unsigned long user_pages  = total_pages - sys_pages;
    unsigned long vp_mapped   = page_table_hits + page_table_from_free + page_faults;

    printf("***** VIRTUAL MEMORY SIMULATION RESULTS *****\n\n");
    printf("Physical Pages Used By SYSTEM: %6lu  \n",
           sys_pages);
    printf("Pages Available to User:       %6lu\n\n", user_pages);

    printf("Virtual Pages Mapped:          %6lu\n", vp_mapped);
    printf("        ------------------------------\n");
    printf("        Page Table Hits:       %6lu \n",
           page_table_hits);
    printf("        Pages from Free:       %6lu \n",
           page_table_from_free);
    printf("        Total Page Faults:     %6lu \n\n",
           page_faults);
}

void print_page_table_usage(char *trace_files[], int ntraces) {
    printf("Page Table Usage Per Process:\n");
    printf("------------------------------\n");
    for (int p = 0; p < ntraces; p++) {
        unsigned long used = 0;
        for (int i = 0; i < PAGE_TABLE_ENTRIES; i++)
            if (page_tables[p][i].valid) used++;
        unsigned long wasted = (PAGE_TABLE_ENTRIES - used) * sizeof(page_table_entry);
        double pct = (double)used * 100.0 / PAGE_TABLE_ENTRIES;

        printf("[%d] %s:\n", p, trace_files[p]);
        printf("    Used Page Table Entries: %6lu  (%.2f%%)\n", used, pct);
        printf("    Page Table Wasted:       %6lu bytes\n\n", wasted);
    }
}



//m3 *****
void print_cache_simulation_results(cache_cv *cv) {
    printf("***** CACHE SIMULATION RESULTS *****\n\n");
    printf("Total Cache Accesses:   %lu\n", total_cache_accesses);
    printf("--- Instruction Bytes: %lu\n", inst_bytes);
    printf("--- SrcDst Bytes:      %lu\n", data_bytes);
    printf("Cache Hits:             %lu\n", cache_hits);
    printf("Cache Misses:           %lu\n", cache_misses);
    printf("--- Compulsory Misses:  %lu\n", compulsory_misses);
    printf("--- Conflict Misses:    %lu\n", conflict_misses);

    double hit_rate  = (double)cache_hits * 100.0 / total_cache_accesses;
    double miss_rate = 100.0 - hit_rate;
    double cpi = (double)total_cycles / inst_count;

    unsigned long total_blocks = (unsigned long)num_sets * associativity;
    unsigned long used_lines   = 0;
    for (int i = 0; i < num_sets; i++) {
        for (int w = 0; w < associativity; w++) {
            if (cache_sets[i][w].valid) used_lines++;
        }
    }
    unsigned long unused_blocks = total_blocks - used_lines;
    double unused_kb  = (double)unused_blocks * block_bytes / 1024.0;

    
    double impl_kb    = (double)cv->memory_size       / 1024.0;
    double unused_pct = (unused_kb / impl_kb) * 100.0;
    double cost_per_kb = cv->cost / impl_kb;
    double waste_cost = unused_kb * cost_per_kb;
    

    printf("***** *****  CACHE HIT & MISS RATE:  ***** *****\n\n");
    printf("Hit  Rate:%22.8f%%  \n",
           hit_rate);
    printf("Miss Rate:%21.4f%%  \n",
           miss_rate);
    printf("CPI:%26.4f Cycles/Instruction  (%lu) \n",
           cpi, total_cycles);
   printf("Unused Cache Space:%10.2f KB / %6.2f KB = %5.2f%%  Waste: $%.2f/chip\n",
+          unused_kb, impl_kb, unused_pct, waste_cost);
}


int main(int argc, char* argv[]) {
    //M3 RAND CALL FIX ME 5/5/2025
  
    srand(time(NULL));
    if((argc <= 16) || (argc > 21)) {
        printf("\t- [USAGE]: VMCacheSim.exe\n");
        printf("\t\t-s <cache size>\n");
        printf("\t\t-b <block size>\n");
        printf("\t\t-a <associativity>\n");
        printf("\t\t-r <replacement policy>\n");
        printf("\t\t-p <physical memory>\n");
        printf("\t\t-u <percentage of physical memory used by the operating ");
        printf("system\n");
        printf("\t\t-n <instructions per time slice>\n");
        printf("\t\t-f <trace file name>\n");
        exit(1);
    }

    cache_ip input_parameters;
    input_parameters.trace_files = (char **) malloc(MAX_TRACE_FILES * 
        sizeof(char *));

    if(input_parameters.trace_files == NULL) {
        printf("\t- [ERROR]: Failed to allocate memory using malloc().\n");
        exit(1);
    }

    int counter = 0;
    int index = 0;

    for(index = 1; index < (argc - 1); index += 2) {
        char identifier = argv[index][1];
        char *input = argv[index + 1];
    
        switch(identifier) {
            case 's':
                specify_cache_size(input, &input_parameters); 
                break;

            case 'b':
                specify_block_size(input, &input_parameters);
                break;

            case 'a':
                specify_associativity(input, &input_parameters);
                break;

            case 'r':
                specify_replacement_policy(input, &input_parameters);
                break;

            case 'p':
                specify_physical_memory(input, &input_parameters);
                break;

            case 'u':
                specify_percent_memory(input, &input_parameters);
                break;

            case 'n':
                specify_instructions(input, &input_parameters);
                break;

            case 'f':
                input_parameters.trace_files[counter++] = input;
                break;

            default:
                printf("\t- [ERROR]: Invalid identifier.\n");
                free_trace_files(&input_parameters);
                exit(1);
        }
    }

    printf("Cache Simulator - CS 3853 - Team #003\n\n");
    
    display_trace_files(&input_parameters, counter);
    display_cache_input_parameters(&input_parameters);

    cache_cv c_calculated_values;
    calculate_total_blocks(&input_parameters, &c_calculated_values);
    calculate_total_rows(&input_parameters, &c_calculated_values);
    calculate_index_size(&c_calculated_values);
    calculate_tag_size(&input_parameters, &c_calculated_values);
    calculate_overhead_size(&c_calculated_values);
    calculate_memory_size(&input_parameters, &c_calculated_values);
    calculate_cost(&c_calculated_values);

    display_cache_calculated_values(&c_calculated_values);
   
    physical_memory_cv pm_calculated_values;
    calculate_total_physical_pages(&input_parameters, &pm_calculated_values);
    calculate_total_system_pages(&input_parameters, &pm_calculated_values);
    calculate_page_table_entry_size(&pm_calculated_values);
    calculate_total_RAM_page_tables(&pm_calculated_values, counter);

    display_physical_memory_calculated_values(&pm_calculated_values);
  
    //m3 display NEED FIX ERRORS WITH UNSIGNED INT FOR SOME REASON 
        
  
  

    init_simulation(&input_parameters, &c_calculated_values);
    for (int pid = 0; pid < counter; pid++) {
        simulate_trace(pid, input_parameters.trace_files[pid]);
    }
    print_vm_results(&input_parameters, counter);
    print_page_table_usage(input_parameters.trace_files, counter);

    
  
    init_simulation(&input_parameters, &c_calculated_values);
    for (int pid = 0; pid < counter; pid++) {
        simulate_trace(pid, input_parameters.trace_files[pid]);
    }
     print_cache_simulation_results(&c_calculated_values);
  
 

    free_trace_files(&input_parameters);
    return 0;
}