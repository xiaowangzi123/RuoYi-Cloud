package com.ruoyi.auth;

import lombok.extern.slf4j.Slf4j;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author wyq
 * @date 2024/11/4
 * @desc nacos密码加密
 */
@Slf4j
public class NacosPwdEncrypt {

    public static void main(String[] args) {
        System.out.println(new BCryptPasswordEncoder().encode("您想要设置的密码"));


        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
//        encryptor.setAlgorithm("PBEWITHHMACSHA512ANDAES_256");
        encryptor.setAlgorithm("PBEWithMD5AndDES");
        encryptor.setPassword("e04c02dda3834bf99745ae3d0d4c1dd7");
        encryptor.setIvGenerator(new RandomIvGenerator());

        // 加密
        String encryptText = encryptor.encrypt("nacos123");
        log.info(":::::|{}", encryptText);

        // 解密
        String decryptText = encryptor.decrypt(encryptText);
        log.info(decryptText);
    }
}
