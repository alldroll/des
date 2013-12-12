#ifndef DES_H
#define DES_H

#include <bitset>

#define KEY_SIZE 56
#define BLOCK_SIZE 64

typedef enum 
{
	ENCRYPT,
	DECRYPT
}DesStateT;

typedef std::bitset<BLOCK_SIZE> BlockT;
typedef std::bitset<KEY_SIZE> KeyT;

extern BlockT des(BlockT x, BlockT k, DesStateT state);
extern BlockT get64bit(const char* c);


#endif //DES_H