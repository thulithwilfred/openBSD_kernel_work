#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

struct Books {
	int name;
	int auth;
};

struct Music {
	int name;
	double len;
	int auth;
};

struct message {
	TAILQ_ENTRY(message) entry;

	int type;
	union {
		struct Music a;
		struct Books b;
	} data;
};

TAILQ_HEAD(message_queue, message) head;




int main(void) {
	struct message *msg, *msg2, *read_msg_pt;
	TAILQ_INIT(&head);

	if (TAILQ_EMPTY(&head)) 
		printf("Empty Queue\n");

	/* 1st Msg */
	msg = malloc(sizeof(struct message));
	msg->type = 0x01; //Music
	msg->data.a.len = 0x03;

	TAILQ_INSERT_TAIL(&head, msg, entry);

	/* 2nd Msg */
	msg2 = malloc(sizeof(struct message));
	msg2->type = 0x02; //Book
	msg2->data.b.name = 0x05;
	msg2->data.b.auth = 0x02;

	TAILQ_INSERT_TAIL(&head, msg2, entry);
		
	
	/* Read Msg 1 */
	read_msg_pt = TAILQ_FIRST(&head);

	if (read_msg_pt->type == 0x01) {
		struct Music m = (struct Music)read_msg_pt->data.a;
		printf("Music\n - Len: %f\n", m.len);
	}

	/* Remove Msg 1 */
	TAILQ_REMOVE(&head, read_msg_pt, entry);
	free(read_msg_pt);

	if (TAILQ_EMPTY(&head)) 
		printf("Much Error\n");

	/* Read MSG 2*/
	read_msg_pt = TAILQ_FIRST(&head);

	if (read_msg_pt->type == 0x02) {
		struct Books b= (struct Books)read_msg_pt->data.b;
		printf("Book\n - Name: %d, Auth: %d\n", b.name, b.auth);
	}

	/* Remove Msg 2 */
	TAILQ_REMOVE(&head, read_msg_pt, entry);
	free(read_msg_pt);

	if (TAILQ_EMPTY(&head)) 
		printf("No new data in queue\n");

	return 0;
}
