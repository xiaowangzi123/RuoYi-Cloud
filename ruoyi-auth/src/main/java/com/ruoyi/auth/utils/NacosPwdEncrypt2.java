package com.ruoyi.auth.utils;

import lombok.extern.slf4j.Slf4j;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.jasypt.iv.RandomIvGenerator;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author wyq
 * @date 2024/11/4
 * @desc nacos密码加密
 */
@Slf4j
public class NacosPwdEncrypt2 {

    public static void main(String[] args) {
        System.out.println(new BCryptPasswordEncoder().encode("PJXp8fZTy1ktEV3S"));


        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setAlgorithm("PBEWITHHMACSHA512ANDAES_256");
//        encryptor.setAlgorithm("PBEWithMD5AndDES");
        encryptor.setPassword("e04c02dda3834bf99745ae3d0d4c1dd7");
        encryptor.setIvGenerator(new RandomIvGenerator());

        // 加密
        String encryptText = encryptor.encrypt("PJXp8fZTy1ktEV3S");
        log.info(":::::|{}", encryptText);

        // 解密
        String decryptText = encryptor.decrypt(encryptText);
        log.info(decryptText);



        PooledPBEStringEncryptor encryptor2 = new PooledPBEStringEncryptor();
        SimpleStringPBEConfig config2 = new SimpleStringPBEConfig();
        config2.setPassword("PJXp8fZTy1ktEV3S"); //加密密码自己定义

        //默认值
        config2.setAlgorithm("PBEWITHHMACSHA512ANDAES_256");
        config2.setKeyObtentionIterations("1000");
        config2.setPoolSize("1");
        config2.setProviderName("SunJCE");
        config2.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");
        config2.setIvGeneratorClassName("org.jasypt.iv.RandomIvGenerator");
        config2.setStringOutputType("base64");
        encryptor2.setConfig(config2);
        System.out.println("beinet 加密后: " + encryptor2.encrypt("NacosPwdEncrypt"));
        System.out.println("beinet 加密后: " + encryptor2.decrypt(encryptor2.encrypt("NacosPwdEncrypt")));
    }
}
