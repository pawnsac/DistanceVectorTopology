#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method:chksum
 * find the chksum of the code

* source: CPS 114: Introduction to Computer Networks   Lecture 4: Reliable Transmission Duke University
 *---------------------------------------------------------------------*/

u_int16_t cksum (const void *_data, int len) {
  const u_int8_t *data = _data;
  u_int32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}

/*---------------------------------------------------------------------
 * Method:check_malloc_error
 * update Check if there is any allocation error 

 *---------------------------------------------------------------------*/
void check_malloc_error(const void *ptr) {
    if (ptr == NULL) {
        fprintf(stderr, "Malloc allocation error\n");
        exit(EXIT_FAILURE);
    }
}
