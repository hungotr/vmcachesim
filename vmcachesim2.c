#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

//CONVERSIONS DONT TOUCH
#define KILOBYTE 1024
#define MEGABYTE (1024 * KILOBYTE)
#define PAGE_SIZE (4 * KILOBYTE)
#define PAGE_TABLE_ENTRIES (512 * KILOBYTE)
#define MAX_TRACE_FILES 3
#define MAX_LINE_SIZE 1024
#define PAGE_SHIFT 12
#define PAGE_MASK 0xFFFFF000

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

typedef struct physical_memory_calculated_values {
    int total_physical_pages;
    int total_system_pages;
    int page_table_entry_size;
    int total_RAM_page_tables;
} physical_memory_cv;

typedef struct page_table_entry {
    int valid;
    int physical_page;
} page_table_entry;

typedef struct process_stats {
    page_table_entry *page_table;
    int used_entries;
    int wasted_bytes;
} process_stats;

typedef struct vm_stats {
    int pages_used_by_system;
    int pages_available;
    int virtual_pages_mapped;
    int page_table_hits;
    int pages_from_free;
    int page_faults;
    process_stats process_data[MAX_TRACE_FILES];
} vm_stats;

//GLOBAL VARIABLES
int *free_physical_pages;
int total_free_pages;

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

void initialize_vm_simulation(physical_memory_cv *pmcv, vm_stats *stats, int num_trace_files);
void run_vm_simulation(cache_ip *ip, physical_memory_cv *pmcv, vm_stats *stats, int num_trace_files);
void display_vm_simulation_results(vm_stats *stats, int num_trace_files, cache_ip *ip);
void cleanup_vm_simulation(vm_stats *stats, int num_trace_files);
int map_virtual_page(int virtual_page, int process_id, vm_stats *stats, physical_memory_cv *pmcv);
int get_free_physical_page();
unsigned int extract_address(char *line);
int parse_trace_line(FILE *fp, unsigned int *address, int *len);

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
    cv->block_offset_size = log2(ip->block_size);
    cv->tag_size = ((log2(ip->physical_memory * MEGABYTE) - cv->index_size) - 
        cv->block_offset_size);
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
        PAGE_SIZE);
}

void calculate_total_system_pages(cache_ip *ip, physical_memory_cv *cv) {
    cv->total_system_pages = ((ip->percent_memory / 100) * 
        cv->total_physical_pages); 
}

void calculate_page_table_entry_size(physical_memory_cv *cv) {
    cv->page_table_entry_size = (log2(cv->total_physical_pages) + 1);

    if (cv->page_table_entry_size < 16) {
        cv->page_table_entry_size = 16;
    }
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

void initialize_vm_simulation(physical_memory_cv *pmcv, vm_stats *stats, int num_trace_files) {
    srand(time(NULL));
    
    stats->pages_used_by_system = pmcv->total_system_pages;
    stats->pages_available = pmcv->total_physical_pages - pmcv->total_system_pages;
    stats->virtual_pages_mapped = 0;
    stats->page_table_hits = 0;
    stats->pages_from_free = 0;
    stats->page_faults = 0;
    
    free_physical_pages = (int*)malloc(sizeof(int) * stats->pages_available);
    if(!free_physical_pages) {
        printf("Failed to allocate memory for free pages list\n");
        exit(1);
    }
    
    for(int i = 0; i < stats->pages_available; i++) {
        free_physical_pages[i] = pmcv->total_system_pages + i;
    }
    total_free_pages = stats->pages_available;
    
    for(int i = 0; i < num_trace_files; i++) {
        stats->process_data[i].page_table = (page_table_entry*)malloc(sizeof(page_table_entry) * PAGE_TABLE_ENTRIES);
        if(!stats->process_data[i].page_table) {
            printf("Failed to allocate memory for page table of process %d\n", i);
            exit(1);
        }
        
        for(int j = 0; j < PAGE_TABLE_ENTRIES; j++) {
            stats->process_data[i].page_table[j].valid = 0;
            stats->process_data[i].page_table[j].physical_page = -1;
        }
        
        stats->process_data[i].used_entries = 0;
        stats->process_data[i].wasted_bytes = 0;
    }
}

int get_free_physical_page() {
    if(total_free_pages <= 0) {
        return -1;
    }
    
    int page_index = rand() % total_free_pages;
    int free_page = free_physical_pages[page_index];
    
    free_physical_pages[page_index] = free_physical_pages[total_free_pages - 1];
    total_free_pages--;
    
    return free_page;
}

int map_virtual_page(int virtual_page, int process_id, vm_stats *stats, physical_memory_cv *pmcv) {
    if(stats->process_data[process_id].page_table[virtual_page].valid) {
        stats->page_table_hits++;
        
        return stats->process_data[process_id].page_table[virtual_page].physical_page;
    }
    
    
    stats->virtual_pages_mapped++; //INC
    
    int physical_page = get_free_physical_page();
    if(physical_page != -1) {
        stats->process_data[process_id].page_table[virtual_page].valid = 1;
        stats->process_data[process_id].page_table[virtual_page].physical_page = physical_page;
        stats->process_data[process_id].used_entries++;
        stats->pages_from_free++;
        return physical_page;
    }
    
    stats->page_faults++;
    return -1;
}

unsigned int extract_address(char *line) {
    unsigned int address = 0;
    
    if (strncmp(line, "EIP", 3) == 0) {
       //USE SSCANF DONT DELETE DONT DELETE DONT DELETE
        sscanf(line, "EIP (%*d): %x", &address);
    } else if (strncmp(line, "dstM:", 5) == 0 || strncmp(line, "srcM:", 5) == 0) {
        
        sscanf(line, "%*s %x", &address);
       
        if(address == 0 || strstr(line, "--------") != NULL)
            address = 0;
    }
    return address;
}


int parse_trace_line(FILE *fp, unsigned int *addresses, int *lengths) {
    char line[MAX_LINE_SIZE];
    char next_line[MAX_LINE_SIZE];
    int count = 0;
    
    // Read eip
    if(fgets(line, MAX_LINE_SIZE, fp) == NULL) {
        return 0;
    }
    
    
    if(strncmp(line, "EIP", 3) == 0) {
       
        unsigned int instr_addr = extract_address(line);
        if(instr_addr != 0) {
            addresses[count] = instr_addr;
            // Extract inS LENG
            int length;
            sscanf(line + 5, "(%d)", &length);
            lengths[count] = length;
            count++;
        }
        
        // Read data access
        if(fgets(next_line, MAX_LINE_SIZE, fp) == NULL) {
            return count;
        }
        
        // Check for dest mem addrr
        char *dst_ptr = strstr(next_line, "dstM:");
        if(dst_ptr) {
            unsigned int dst_addr = extract_address(dst_ptr);
            if(dst_addr != 0) {
                addresses[count] = dst_addr;
                lengths[count] = 4;  // Always 4 BYTES DONT TOUCH
                count++;
            }
        }
        
        // Check source
        char *src_ptr = strstr(next_line, "srcM:");
        if(src_ptr) {
            unsigned int src_addr = extract_address(src_ptr);
            if(src_addr != 0) {
                addresses[count] = src_addr;
                lengths[count] = 4;  // Always 4
                count++;
            }
        }
    }
    
    return count;
}

void run_vm_simulation(cache_ip *ip, physical_memory_cv *pmcv, vm_stats *stats, int num_trace_files) {
    char line[MAX_LINE_SIZE];
    unsigned int address;
    
    for (int proc_id = 0; proc_id < num_trace_files; proc_id++) {
        FILE *fp = fopen(ip->trace_files[proc_id], "r");
        if (!fp) {
            printf("Failed to open trace file: %s\n", ip->trace_files[proc_id]);
            continue;
        }
        
        
        while (fgets(line, MAX_LINE_SIZE, fp) != NULL) {
            // Process EIP line
            if (strncmp(line, "EIP", 3) == 0) {
                address = extract_address(line);
                if (address != 0) {
                    unsigned int virtual_page = address >> PAGE_SHIFT;
                    if (virtual_page < PAGE_TABLE_ENTRIES) {
                        map_virtual_page(virtual_page, proc_id, stats, pmcv);
                    }
                }
                
               
                if (fgets(line, MAX_LINE_SIZE, fp) != NULL) {
                    // dest address 
                    if (strncmp(line, "dstM:", 5) == 0) {
                        address = extract_address(line);
                        if (address != 0) {
                            unsigned int virtual_page = address >> PAGE_SHIFT;
                            if (virtual_page < PAGE_TABLE_ENTRIES) {
                                map_virtual_page(virtual_page, proc_id, stats, pmcv);
                            }
                        }
                    }
                    
                   
                    char *src_ptr = strstr(line, "srcM:");
                    if (src_ptr != NULL) {
                        address = extract_address(src_ptr);
                        if (address != 0) {
                            unsigned int virtual_page = address >> PAGE_SHIFT;
                            if (virtual_page < PAGE_TABLE_ENTRIES) {
                                map_virtual_page(virtual_page, proc_id, stats, pmcv);
                            }
                        }
                    }
                }
            }
        }
        
        // Calculate waste b
        stats->process_data[proc_id].wasted_bytes = (PAGE_TABLE_ENTRIES - stats->process_data[proc_id].used_entries) *
                                                    (pmcv->page_table_entry_size / 8);
        fclose(fp);
    }
}
void display_vm_simulation_results(vm_stats *stats, int num_trace_files, cache_ip *ip) {
    printf("***** VIRTUAL MEMORY SIMULATION RESULTS *****\n\n");
    printf("Physical Pages Used By SYSTEM: %d\n", stats->pages_used_by_system);
    printf("Pages Available to User: %d\n", stats->pages_available);
     printf("Virtual Pages Mapped: %d\n",
           stats->page_table_hits 
         + stats->pages_from_free 
         + stats->page_faults);
    printf("------------------------------\n");
    printf("Page Table Hits: %d\n", stats->page_table_hits);
    printf("Pages from Free: %d\n", stats->pages_from_free);
    printf("Total Page Faults: %d\n", stats->page_faults);
    printf("\nPage Table Usage Per Process:\n");
    printf("------------------------------\n");
    
    for(int i = 0; i < num_trace_files; i++) {
        printf("[%d] %s:\n", i, ip->trace_files[i]);
        printf("    Used Page Table Entries: %d (%.2f%%)\n", 
               stats->process_data[i].used_entries, 
               (double)stats->process_data[i].used_entries / PAGE_TABLE_ENTRIES * 100);
        printf("    Page Table Wasted: %d bytes\n", stats->process_data[i].wasted_bytes);
    }
    printf("\n");
}

void cleanup_vm_simulation(vm_stats *stats, int num_trace_files) {
    for(int i = 0; i < num_trace_files; i++) {
        free(stats->process_data[i].page_table);
    }
    free(free_physical_pages);
}

int main(int argc, char* argv[]) {
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

    printf("Cache Simulator - CS 3853 - Team #03\n\n");
    
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
    
    vm_stats stats;
    initialize_vm_simulation(&pm_calculated_values, &stats, counter);
    run_vm_simulation(&input_parameters, &pm_calculated_values, &stats, counter);
    display_vm_simulation_results(&stats, counter, &input_parameters);
    cleanup_vm_simulation(&stats, counter);

    free_trace_files(&input_parameters);
    return 0;
}