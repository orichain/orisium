#include <stdio.h>

#include "master/process.h"

int main() {
	printf("[Orisium]: ==========================================================\n");
    printf("[Orisium]: Orisium dijalankan.\n");
    printf("[Orisium]: ==========================================================\n");
    
	run_master_process();
	
	printf("[Orisium]: ==========================================================\n");
    printf("[Orisium]: Orisium selesai dijalankan.\n");
    printf("[Orisium]: ==========================================================\n");
    
    return 0;
}
