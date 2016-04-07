---
layout: post
title:  "在IOS9中使用KeychainTouchID"
date:   2016-04-05 16:08:08 +0800
categories: develop ios
---

##前言
在IOS9之前如果我们想做指纹认证的功能，只能完全信任客户端的结果，如果客户端被破解那么指纹验证就可能不绕过。但是这一切在IOS9之后有改观，后台服务器也能参与认证的过程了，接下来我们会详细介绍。

##关键点
1.在IOS9之后苹果对keychain进行了改进，keychain的敏感数据迁移到Secure Enclave中。参考[wwdc2015 Security and Privacy](https://developer.apple.com/videos/play/wwdc2015/706/)

2. `SecGenerateKeyPair` : 该方法用于生成RSA或者ECC非对称密钥。IOS9之后指定参数`kSecAttrTokenIDSecureEnclave` 和 `kSecAttrKeyTypeEC`可以产生ECC的非对称密钥对，公钥会返回给程序，私钥直接送到Secure Enclave中，任何用户都无法获取私钥，只能通过`SecKeyRawSign`方法来请求签名，同时我们可以设置ACL说明使用Touch ID来保护私钥。

3. `SecKeyRawSign` : 使用ECDSA算法来签名数据，

  [video](https://developer.apple.com/videos/play/wwdc2015/706/)

  [TouchIDKeyChainDemo](https://developer.apple.com/library/ios/samplecode/KeychainTouchID/Introduction/Intro.html#//apple_ref/doc/uid/TP40014530-Intro-DontLinkElementID_2)

    	CFErrorRef error = NULL;
		Sec AccessControlRef sacObject;
		//访问控制链表
		sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
		                                            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
		                                            kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage, &error);
		
		// 密钥参数
		NSDictionary *parameters = @{
		    (__bridge id)kSecAttrTokenID: (__bridge id)kSecAttrTokenIDSecureEnclave, //私钥存入SE
		    (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeEC, //如果要使用SE，这里只能指定kSecAttrKeyTypeEC
		    (__bridge id)kSecAttrKeySizeInBits: @256,
		    (__bridge id)kSecPrivateKeyAttrs: @{
		        (__bridge id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
		        (__bridge id)kSecAttrIsPermanent: @YES,
		        (__bridge id)kSecAttrLabel: @"my-se-key", //密钥名
		    },
		};
		
		//产生公私钥对
		SecKeyRef publicKey, privateKey;
		OSStatus status = SecKeyGeneratePair((__bridge CFDictionaryRef)parameters, &publicKey, &privateKey);
		//将公钥保存下来

注意，publicKey是返回的公钥，privateKey是私钥的token，我们只能用privateKey来请求签名数据。


4.上一步得到的publicKey的并不是真正的公钥数据，这里我们需要先把publicKey保存到keychain就能得到真正的公钥数据了，下面是简单的代码片段：

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

5.dataRef就是我们得到的真正的公钥数据，我们把他转成PEM格式


[KeychainTouchIDDemoUrl]:https://developer.apple.com/library/ios/samplecode/KeychainTouchID/Introduction/Intro.html