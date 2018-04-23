#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cipher.h"
 

int str2Int(char* strIn, int strLen)
{
   int i = 0;
   int temp = 0;
   while((strIn[i]!='\0') && (i<strLen)){
      temp = temp * 10 + (int)(strIn[i]) - 48;
      i = i+1;
   }
   return temp;
}

int str2longlong(char* strIn, long long* longOut, int strLen){
   int i = 0;
   long long num = 0;
   while((strIn[i]!='\0') && (i<strLen)){
      num = ((strIn[i] >= '0') && (strIn[i] <= '9')) ? (num*16 + (long long)(strIn[i]-48)) : 
                                                       (num*16 + (long long)(strIn[i]-'a' + 10));
      i = i+1;
   }
   *longOut = num;
   return 0;
}

int longlong2bits(long long* longIn, char* strOut, int strLen){
   int i = 0;
   long long temp = *longIn;
   for(i=0;i<strLen;i++){
      strOut[i] = (temp%2 == 0) ? '0' : '1';
      temp = (temp%2 == 0) ? temp/2 : (temp-1)/2;
   }
   return 0;
}

int bits2longlong(long long* longOut, char* strIn, int strLen){
   long long temp = 0;
   int i;
   for (i=0;i<strLen;i++){
      temp = (strIn[63-i] == '0') ? temp*2 : temp*2+1;
   }
   *longOut = temp;
}

int nxt_Bits(char* oldBits, char* newBits){
   int i = 0;
   newBits[0] = oldBits[31];
   newBits[1] = oldBits[0];
   newBits[2] = (oldBits[1] == oldBits[31]) ? '0' : '1';
   for(i=3;i<6;i++){
      newBits[i] = oldBits[i-1];
   }
   newBits[6] = (oldBits[5] == oldBits[31]) ? '0' : '1';
   newBits[7] = (oldBits[6] == oldBits[31]) ? '0' : '1';
   for(i=8;i<32;i++){
      newBits[i] = oldBits[i-1];
   }
   newBits[32] = oldBits[63];
   newBits[33] = oldBits[32];
   newBits[34] = (oldBits[33] == oldBits[63]) ? '0' : '1';
   for(i=35;i<38;i++){
      newBits[i] = oldBits[i-1];
   }
   newBits[38] = (oldBits[37] == oldBits[63]) ? '0' : '1';
   newBits[39] = (oldBits[38] == oldBits[63]) ? '0' : '1';
   for(i=40;i<64;i++){
      newBits[i] = oldBits[i-1];
   }
}

int nxt_Value(long long* old_l, long long* new_l){
   unsigned char oldBits[64+1],newBits[64+1];
   memset(oldBits,0,sizeof(oldBits));
   memset(newBits,0,sizeof(newBits));
   longlong2bits(old_l,oldBits,64);
   nxt_Bits(oldBits,newBits);
   bits2longlong(new_l,newBits,64);
   return 0;
}

int des_key_init(char* keyTableBase, int keyTableSize, long long initSeed){
   long long* tableIndex;
   long long seed_l,seed_l_nxt;
   int i;
   seed_l = initSeed;
   tableIndex = (long long*)keyTableBase;
   for(i = 0;i<keyTableSize;i++){
      *tableIndex = seed_l;
      nxt_Value(&seed_l,&seed_l_nxt);
      seed_l = seed_l_nxt;
      tableIndex++;
   }
   return 0;
}

//userID[0] for songhui
//userID[1] for pkt type
//userID[2-15] for get des key
int get_key_from_userID(char* userID,long long* key,char* keyTableBase){
   long long keyOffset = 0;
   long long temp = 0;
   int i;
   int shift = 0;
   long long *key_ptr;

   char temp1UserID[8] = {
      userID[15], userID[14], userID[13], userID[12],
      userID[11], userID[10], userID[9],  userID[8]
   };
   char temp2UserID[8] = {
      userID[8], userID[7], userID[6], userID[5], 
      userID[4], userID[3], userID[2], userID[1]
   };

   for(i=0;i<4;i++){
      temp = *(long long*)(temp1UserID);
      temp = temp >> shift;
      temp = temp & 0x3fff;
      keyOffset = keyOffset ^ temp;
      shift+=14;
   }
   shift = 0;
   for(i=0;i<4;i++){
      temp = *(long long*)(temp2UserID);
      temp = temp >> shift;
      temp = temp & 0x3fff;
      keyOffset = keyOffset ^ temp;
      shift+=14;
   }

   key_ptr = (long long*) keyTableBase + (keyOffset % TABLE_SIZE);
   *key = *key_ptr;

   return 0;
}

int longlong2char(long long longIn,char* strOut){
   int i;
   for(i=0; i<8; i++){
      *strOut = (char)(longIn & 0xff);
      strOut++;
      longIn = longIn >> 8;
   }
   return 0;
}

int cal_nonzero_bits(int dataIn){
   int i = 0;
   int result = 0;
   for(i=0;i<32;i++){
      if (dataIn == 0) break;
      if ((dataIn % 2) == 1){
         result ++;
         dataIn = (dataIn-1)/2;
      }
      else{
         dataIn = dataIn/2;
      }
   }
   return result;
}

int own_encrypt(char* strIn, char* strOut, long long key){
   char clr_0[4] = {strIn[0], strIn[1], (char)(0x00), (char)(0x00)};
   char clr_1[4] = {strIn[2], strIn[3], (char)(0x00), (char)(0x00)};
   char clr_2[4] = {strIn[4], strIn[5], (char)(0x00), (char)(0x00)};
   char clr_3[4] = {strIn[6], strIn[7], (char)(0x00), (char)(0x00)};
   unsigned int key0,key1,key2,key3;
   unsigned int clr_data0,clr_data1,clr_data2,clr_data3;
   unsigned int xor_r10,xor_r11,xor_r12,xor_r13;
   unsigned int xor_r20,xor_r21,xor_r22,xor_r23;
   unsigned int lp_left_r0,lp_left_r1,lp_left_r2,lp_left_r3;
   unsigned int one_cnt0,one_cnt1,one_cnt2,one_cnt3;
   long long result;

   key0 = key & 0x000000000000ffff;
   key1 = (key >> 16) & 0x000000000000ffff;
   key2 = (key >> 32) & 0x000000000000ffff;
   key3 = (key >> 48) & 0x000000000000ffff;

   one_cnt0 = cal_nonzero_bits(key0);
   one_cnt1 = cal_nonzero_bits(key1);
   one_cnt2 = cal_nonzero_bits(key2);
   one_cnt3 = cal_nonzero_bits(key3);

   clr_data0 = *(int*)clr_0;
   clr_data1 = *(int*)clr_1;
   clr_data2 = *(int*)clr_2;
   clr_data3 = *(int*)clr_3;

   xor_r10 = ENCRYPT ^ clr_data0;
   lp_left_r0 = xor_r10 << one_cnt0;
   xor_r20 = (lp_left_r0 >> 16) ^ (lp_left_r0 & 0x0000ffff) ^ key0;

   xor_r11 = xor_r20 ^ clr_data1;
   lp_left_r1 = xor_r11 << one_cnt1;
   xor_r21 = (lp_left_r1 >> 16) ^ (lp_left_r1 & 0x0000ffff) ^ key1;

   xor_r12 = xor_r21 ^ clr_data2;
   lp_left_r2 = xor_r12 << one_cnt2;
   xor_r22 = (lp_left_r2 >> 16) ^ (lp_left_r2 & 0x0000ffff) ^ key2;

   xor_r13 = xor_r22 ^ clr_data3;
   lp_left_r3 = xor_r13 << one_cnt3;
   xor_r23 = (lp_left_r3 >> 16) ^ (lp_left_r3 & 0x0000ffff) ^ key3;

   result = xor_r23;
   result = result << 16 | xor_r22;
   result = result << 16 | xor_r21;
   result = result << 16 | xor_r20;

   longlong2char(result,strOut);
   return 0;
}

int own_decrypt(char* strIn, char* strOut, long long key){
   char clr_0[4] = {strIn[0], strIn[1], (char)(0x00), (char)(0x00)};
   char clr_1[4] = {strIn[2], strIn[3], (char)(0x00), (char)(0x00)};
   char clr_2[4] = {strIn[4], strIn[5], (char)(0x00), (char)(0x00)};
   char clr_3[4] = {strIn[6], strIn[7], (char)(0x00), (char)(0x00)};
   unsigned int key0,key1,key2,key3;
   unsigned int clr_data0,clr_data1,clr_data2,clr_data3;
   unsigned int xor_r10,xor_r11,xor_r12,xor_r13;
   unsigned int xor_r20,xor_r21,xor_r22,xor_r23;
   unsigned int lp_right_r0,lp_right_r1,lp_right_r2,lp_right_r3;
   unsigned int one_cnt0,one_cnt1,one_cnt2,one_cnt3;
   long long result;

   key0 = key & 0x000000000000ffff;
   key1 = (key >> 16) & 0x000000000000ffff;
   key2 = (key >> 32) & 0x000000000000ffff;
   key3 = (key >> 48) & 0x000000000000ffff;

   one_cnt0 = cal_nonzero_bits(key0);
   one_cnt1 = cal_nonzero_bits(key1);
   one_cnt2 = cal_nonzero_bits(key2);
   one_cnt3 = cal_nonzero_bits(key3);

   clr_data0 = *(int*)clr_0;
   clr_data1 = *(int*)clr_1;
   clr_data2 = *(int*)clr_2;
   clr_data3 = *(int*)clr_3;

   xor_r10 = key0 ^ clr_data0;
   xor_r11 = key1 ^ clr_data1;
   xor_r12 = key2 ^ clr_data2;
   xor_r13 = key3 ^ clr_data3;

   lp_right_r0 = (xor_r10 << 16) >> one_cnt0;
   lp_right_r1 = (xor_r11 << 16) >> one_cnt1;
   lp_right_r2 = (xor_r12 << 16) >> one_cnt2;
   lp_right_r3 = (xor_r13 << 16) >> one_cnt3;

   xor_r20 = (lp_right_r0 >> 16) ^ (lp_right_r0 & 0x0000ffff) ^ ENCRYPT;
   xor_r21 = (lp_right_r1 >> 16) ^ (lp_right_r1 & 0x0000ffff) ^ clr_data0;
   xor_r22 = (lp_right_r2 >> 16) ^ (lp_right_r2 & 0x0000ffff) ^ clr_data1;
   xor_r23 = (lp_right_r3 >> 16) ^ (lp_right_r3 & 0x0000ffff) ^ clr_data2;

   result = xor_r23;
   result = result << 16 | xor_r22;
   result = result << 16 | xor_r21;
   result = result << 16 | xor_r20;

   longlong2char(result,strOut);
   return 0;
}
