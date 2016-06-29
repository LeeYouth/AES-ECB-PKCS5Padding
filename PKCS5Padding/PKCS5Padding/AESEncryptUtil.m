//
//  AESEncryptUtil.m
//  PKCS5Padding
//
//  Created by LYoung on 16/6/29.
//  Copyright © 2016年 LYoung. All rights reserved.
//

#import "AESEncryptUtil.h"
#import <CommonCrypto/CommonCryptor.h>

@implementation AESEncryptUtil

//字符串加密(16进制)
+ (NSString *)encyptPKCS5:(NSString *)plainText WithKey:(NSString *)key{
    
    //把string 转NSData
    NSData* data = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    
    //length
    size_t plainTextBufferSize = [data length];
    
    const void *vplainText = (const void *)[data bytes];
    
    
    uint8_t *bufferPtr = NULL;
    size_t bufferPtrSize = 0;
    size_t movedBytes = 0;
    
    bufferPtrSize = (plainTextBufferSize + kCCBlockSizeAES128) & ~(kCCBlockSizeAES128 - 1);
    bufferPtr = malloc( bufferPtrSize * sizeof(uint8_t));
    memset((void *)bufferPtr, 0x0, bufferPtrSize);
    
    const void *vkey = (const void *) [key UTF8String];
    //配置CCCrypt
    CCCryptorStatus ccStatus = CCCrypt(kCCEncrypt,
                                       kCCAlgorithmAES128, //3DES
                                       kCCOptionECBMode|kCCOptionPKCS7Padding, //设置模式
                                       vkey,    //key
                                       kCCKeySizeAES128,
                                       nil,     //偏移量，这里不用，设置为nil;不用的话，必须为nil,不可以为@“”
                                       vplainText,
                                       plainTextBufferSize,
                                       (void *)bufferPtr,
                                       bufferPtrSize,
                                       &movedBytes);
    
    if (ccStatus == kCCSuccess) {
        NSData *myData = [NSData dataWithBytes:(const char *)bufferPtr length:(NSUInteger)movedBytes];
        
        //16进制(你也可以换成base64等)
        NSUInteger          len = [myData length];
        char *              chars = (char *)[myData bytes];
        NSMutableString *   hexString = [[NSMutableString alloc] init];

        for(NSUInteger i = 0; i < len; i++ )
            [hexString appendString:[NSString stringWithFormat:@"%0.2hhx", chars[i]]];
        return hexString;
    }
    
    free(bufferPtr);
    return nil;
    
}


@end
