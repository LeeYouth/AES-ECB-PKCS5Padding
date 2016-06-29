//
//  AESEncryptUtil.h
//  PKCS5Padding
//
//  Created by LYoung on 16/6/29.
//  Copyright © 2016年 LYoung. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface AESEncryptUtil : NSObject

/** AES/ECB/PKSC5Padding 加密 */
+ (NSString *)encyptPKCS5:(NSString *)plainText WithKey:(NSString *)key;

@end
