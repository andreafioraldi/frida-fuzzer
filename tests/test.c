#include <stdio.h>
#include <assert.h>

int target_func(char* buf, int size) {
    
  switch (buf[0]) {
    case 1:
      if(buf[1]=='\x44') {
         *(char*)(0) = 1;
      }
      break;
    case '\xfe':
      if(buf[4]=='\xf0') {
          assert(0);
      }
      break;
    case 0xff:
      if(buf[2]=='\xff') {
        sleep(2);
      }
      break;
    default:
      break;
  }

  return 1;
}

int main() {

  while (1)
    sleep(1);

  return 0;

}

