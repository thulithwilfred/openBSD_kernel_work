#include <stdio.h>
/* 
 *function prototypes
 */
int echo(int);

/**
 * @brief Main program to demonstrate basic function call, and print
 * 
 * @param argc arg count
 * @param argv args
 * @return int 0 on succes (exit status)
 */
int main (int argc, char** argv) {
    printf("Here be dragons... %d\n", echo(3301));
    return 0;
}

/**
 * @brief Function to return its argument 
 * 
 * @param toEcho num to be echod back
 * @return int same as toEcho
 */
int echo(int toEcho) {
    return toEcho;
}