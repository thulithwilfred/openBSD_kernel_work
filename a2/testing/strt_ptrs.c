#include <stdlib.h>
#include <stdio.h>

struct maps {
	int longitude;
};

void tester(void *mp) {
	struct maps k, *x;

	k = *(struct maps*)mp;
	k.longitude = 69;
	
	x = (struct maps*)mp;
	x->longitude = 420;

}

int main(void) {
	struct maps k = {0};
	k.longitude = 111;

	printf("before: %d\n", k.longitude);
	tester((void*)&k);
	printf("after: %d\n", k.longitude);
	return(0);
}
