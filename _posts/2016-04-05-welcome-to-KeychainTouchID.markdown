---
layout: post
title:  "在IOS9中使用KeychainTouchID"
date:   2016-04-05 16:08:08 +0800
categories: develop ios
---

## 前言

在IOS9之前如果我们想做指纹认证的功能，只能完全信任客户端的结果，如果客户端被破解那么指纹验证就可能被绕过。但是这一切在IOS9之后有了改观，后台服务器也能参与认证的过程了，接下来我们会详细介绍。

## 关键点

1. 在IOS9之后苹果对keychain进行了改进，支持密钥的产生和使用在Secure Enclave中进行。具体可以参考[wwdc2015 Security and Privacy](https://developer.apple.com/videos/play/wwdc2015/706/)

2. `SecGenerateKeyPair` : 可以产生ECC P256的非对称密钥对，如果公钥会返回给程序私钥直接送到Secure Enclave中，任何用户都无法获取私钥，只能通过 SecKeyRawSign 方法来请求签名，同时我们可以使用 SecAccessControlCreateWithFlags 来设置如果要使用私钥必须验证Touch ID。

3. `SecKeyRawSign` : 使用ECDSA数字签名算法来签名数据(注意这里是数字签名算法，不只是ECC加密)。

4. 如何使用 SecGenerateKeyPair 和 SecKeyRawSign 请参考[TouchIDKeyChainDemo](https://developer.apple.com/library/ios/samplecode/KeychainTouchID/Introduction/Intro.html#//apple_ref/doc/uid/TP40014530-Intro-DontLinkElementID_2)

## 服务器如何参与验证指纹认证

1. 客户端调用SecGenerateKeyPair产生密钥对。

2. 将公钥上送到服务器进行存储。

3. 服务器发送报文到客户端请求签名。

4. 客户端使用SecKeyRawSign进行签名，这里系统会自动调用Touch ID并要求用户验证指纹。

5. 客户端将签名结果上送到服务器。

6. 服务器使用公钥来验证签名。

## 使用openssl验签demo

	#define Secp256r1CurveLen     256

	unsigned char Secp256r1header[] =
	{
	    0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
	    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
	    0x01, 0x06, 0x08, 0x2A, 0x86, 0x48,
	    0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03,
	    0x42, 0x00
	};

	#define Secp256r1headerLen    26
	#define PublicKeyInitialTag       @"-----BEGIN PUBLIC KEY-----\n"
	#define PublicKeyFinalTag         @"\n-----END PUBLIC KEY-----"

    
    //产生密钥
	- (void)generateKeyAsync {
    
	    CFErrorRef error = NULL;
	    SecAccessControlRef sacObject;
	    
	    //设置ACL，使用kSecAccessControlTouchIDAny表示使用Touch ID来保护密钥。
	    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
	                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
	                                                kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage, &error);
	    
	    NSDictionary *parameters = @{
	                                 (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,//表示使用SecureEnclave来保存密钥
	                                 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC,//表示产生ECC密钥对，注意目前只支持256位的ECC算法
	                                 (__bridge id)kSecAttrKeySizeInBits: @256,
	                                 (__bridge id)kSecPrivateKeyAttrs: @{
	                                         (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
	                                         (__bridge id)kSecAttrIsPermanent: @YES,
	                                         (__bridge id)kSecAttrLabel: @"my-se-key",
	                                         },
	                                 };
	    
	    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
	        SecKeyRef publicKey, privateKey;
	        OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
	        if (status == errSecSuccess) {
	            NSLog(@"产生密码成功");
	            
	            //这里先把公钥保存到keychain才能拿到真正的公钥数据
	            NSDictionary *pubDict = @{
	                                      (__bridge id)kSecClass              : (__bridge id)kSecClassKey,
	                                      (__bridge id)kSecAttrKeyType        : (__bridge id)kSecAttrKeyTypeEC,
	                                      (__bridge id)kSecAttrLabel          : @"",
	                                      (__bridge id)kSecAttrIsPermanent    : @(YES),
	                                      (__bridge id)kSecValueRef           : (__bridge id)publicKey,
	                                      (__bridge id)kSecAttrKeyClass       : (__bridge id)kSecAttrKeyClassPublic,
	                                      (__bridge id)kSecReturnData         : @(YES)
	                                      };
	            
	            CFTypeRef dataRef = NULL;
	            status = SecItemAdd((__bridge CFDictionaryRef)pubDict, &dataRef);
	            if(status == errSecSuccess){
	                NSLog(@"导出公钥成功");

                    //下面是将公钥转换为PEM格式,为了后面使用openssl验证签名
                    //PEM格式 = PublicKeyInitialTag +  Base64(Secp256r1header + publicKeyData) + PublicKeyFinalTag
	                NSData *publicKeyData = (__bridge NSData *)dataRef;
	                NSLog(@"publicKeyData :%@",publicKeyData);
	                NSMutableData *data = [NSMutableData dataWithBytes:Secp256r1header
	                                                            length:sizeof(Secp256r1header)];
	                [data appendData:publicKeyData];
	                NSString *base64String = [data base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
	                NSMutableString *publicKeyStr = [NSMutableString string];
	                [publicKeyStr appendString:PublicKeyInitialTag];
	                [publicKeyStr appendString:base64String];
	                [publicKeyStr appendString:PublicKeyFinalTag];
	                self.pubKey = publicKeyStr;
	                NSLog(@"%@",self.pubKey);
	            }else{
	                NSLog(@"导出公钥失败");
	            }

	            CFRelease(dataRef);
	            CFRelease(privateKey);
	            CFRelease(publicKey);
	        }else{
	            NSLog(@"产生密码失败");
	        }
	    });
	}


    //使用密钥
	- (void)useKeyAsync {

	    NSDictionary *query = @{
	                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
	                            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
	                            (__bridge id)kSecAttrLabel: @"my-se-key",
	                            (__bridge id)kSecReturnRef: @YES,
	                            (__bridge id)kSecUseOperationPrompt: @"验证签名"
	                            };

	    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
	        SecKeyRef privateKey;
	        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);
	        
	        if (status == errSecSuccess) {
	            uint8_t sign[128];
	            size_t signatureLength = sizeof(sign);
	            uint8_t dataToSign[200];
	            uint8_t hash[CC_SHA1_DIGEST_LENGTH];
	            CC_SHA256(dataToSign, CC_SHA1_DIGEST_LENGTH, hash);
	            
	            //调用SecKeyRawSign的时候系统会自动调起Touch ID验证用户指纹
	            //指纹的验证和数据的签名都在Secure Enclave中进行保证了安全
	            status = SecKeyRawSign(privateKey, kSecPaddingPKCS1, dataToSign, sizeof(dataToSign), sign, &signatureLength);
	            if (status == errSecSuccess) {
	                NSLog(@"SecKeyRawSign签名数据成功");
	                
	                //使用openSSL验证签名
	                const char *pemPubKey = [self.pubKey UTF8String];
	                BIO *buf = BIO_new_mem_buf((void*)pemPubKey, (int)self.pubKey.length);
	                EC_KEY *ecKey = PEM_read_bio_EC_PUBKEY(buf, NULL, NULL, NULL);
	                EC_KEY_print_fp(stdout, ecKey, 2);
	                
	                int ret = ECDSA_verify(0, dataToSign, sizeof(dataToSign),sign, (int)signatureLength, ecKey);
	                if (ret == 1) {
	                    NSLog(@"openssl 验证签名成功");
	                }else{
	                    NSLog(@"openssl 验证签名失败");
	                }
	            }
	            CFRelease(privateKey);
	        }
	        else {
	            NSLog(@"SecKeyRawSign签名数据失败");
	        }
	    });
	}

	//删除密钥
	- (void)deleteKeyAsync {

	    NSDictionary *query = @{
	                            (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave,
	                            (__bridge id)kSecClass: (__bridge id)kSecClassKey,
	                            (__bridge id)kSecAttrKeyClass: (__bridge id)kSecAttrKeyClassPrivate,
	                            (__bridge id)kSecAttrLabel: @"my-se-key",
	                            (__bridge id)kSecReturnRef: @YES,
	                            };	  
	    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
	        OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
	        if(status == errSecSuccess){
	            NSLog(@"delete success");
	        }else{
	            NSLog(@"delete fail");
	        }
	    });
	}

## 备注

1. 我测试发现如果多次调用generateKeyAsync且kSecAttrLabel不变，使用SecKeyRawSign可以签名成功，但是使用openssl验签就会失败，所以在调用generateKeyAsync之前先调用deleteKeyAsync。

2. openssl的ios库可以使用[OpenSSL-for-iPhone](https://github.com/x2on/OpenSSL-for-iPhone/)，一个命令就可以自动打包，非常方便。
