package org.zz.gmhelper.cert.test;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.*;
import org.zz.gmhelper.cert.exception.InvalidX500NameException;
import org.zz.gmhelper.test.util.FileUtil;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.security.*;
import java.security.cert.X509Certificate;

public class SM2X509CertMakerTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * 生成SM2单证书
     */
    @Test
    public void testMakeCertificate() {
        try {
            // 生成密钥对
            KeyPair subKP = SM2Util.generateKeyPair();
            // 配置DN
            X500Name subDN = buildSubjectDN();
            // 构建SM2PublicKey
            SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
                    (BCECPublicKey) subKP.getPublic());
            // 创建证书请求
            byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
                    SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();

            // 保存证书请求
            PKCS10CertificationRequest pkcs10CertRequest = new PKCS10CertificationRequest(csr);
            saveCSRAsPEM("target/test.sign.pem", pkcs10CertRequest);
            savePriKey("target/test.sm2.pri", (BCECPrivateKey) subKP.getPrivate(),
                    (BCECPublicKey) subKP.getPublic());

            SM2X509CertMaker certMaker = buildCertMaker();
            X509Certificate cert = certMaker.makeSSLEndEntityCert(csr);
            FileUtil.writeFile("target/test.sm2.cer", cert.getEncoded());
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testCSRToPEM() throws Exception {
        // 生成密钥对
        KeyPair subKP = SM2Util.generateKeyPair();
        // 配置DN
        X500Name subDN = buildSubjectDN();
        // 构建SM2PublicKey
        SM2PublicKey sm2SubPub = new SM2PublicKey(subKP.getPublic().getAlgorithm(),
                (BCECPublicKey) subKP.getPublic());
        // 创建证书请求
        byte[] csr = CommonUtil.createCSR(subDN, sm2SubPub, subKP.getPrivate(),
                SM2X509CertMaker.SIGN_ALGO_SM3WITHSM2).getEncoded();
        PKCS10CertificationRequest pkcs10CertRequest = new PKCS10CertificationRequest(csr);
        saveCSRAsPEM("target/test.sign.pem", pkcs10CertRequest);
        saveCSRAsDER("target/test.sign.der", pkcs10CertRequest);
    }

    // 将证书请求保存为PEM编码
    private static void saveCSRAsPEM(String filePath, PKCS10CertificationRequest pkcs10CertRequest) throws IOException {
        // 将 PKCS#10 证书请求转换为 PEM 格式
        StringWriter stringWriter = new StringWriter();
        try (PEMWriter pemWriter = new PEMWriter(stringWriter)) {
            pemWriter.writeObject(pkcs10CertRequest);
        }

        // 将 PEM 格式数据写入文件
        try (FileWriter fileWriter = new FileWriter(filePath)) {
            fileWriter.write(stringWriter.toString());
        }
    }

    // 将证书请求保存为DER编码
    private static void saveCSRAsDER(String filePath, PKCS10CertificationRequest pkcs10CertRequest) throws IOException {
        // 将 PKCS#10 证书请求对象转换为 DER 编码的字节数组
        byte[] derEncoded = pkcs10CertRequest.getEncoded();

        // 将 DER 编码的字节数组保存到文件
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(derEncoded);
        }
    }


    public static void savePriKey(String filePath, BCECPrivateKey priKey, BCECPublicKey pubKey) throws IOException {
        ECPrivateKeyParameters priKeyParam = BCECUtil.convertPrivateKeyToParameters(priKey);
        ECPublicKeyParameters pubKeyParam = BCECUtil.convertPublicKeyToParameters(pubKey);
        byte[] derPriKey = BCECUtil.convertECPrivateKeyToSEC1(priKeyParam, pubKeyParam);
        FileUtil.writeFile(filePath, derPriKey);
    }

    public static X500Name buildSubjectDN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        builder.addRDN(BCStyle.CN, "example.org");
        builder.addRDN(BCStyle.EmailAddress, "abc@example.org");
        return builder.build();
    }

    public static X500Name buildRootCADN() {
        X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        builder.addRDN(BCStyle.C, "CN");
        builder.addRDN(BCStyle.O, "org.zz");
        builder.addRDN(BCStyle.OU, "org.zz");
        builder.addRDN(BCStyle.CN, "ZZ Root CA");
        return builder.build();
    }

    public static SM2X509CertMaker buildCertMaker() throws InvalidAlgorithmParameterException,
            NoSuchAlgorithmException, NoSuchProviderException, InvalidX500NameException {
        X500Name issuerName = buildRootCADN();
        KeyPair issKP = SM2Util.generateKeyPair();
        long certExpire = 20L * 365 * 24 * 60 * 60 * 1000; // 20年
        CertSNAllocator snAllocator = new RandomSNAllocator(); // 实际应用中可能需要使用数据库来保证证书序列号的唯一性。
        return new SM2X509CertMaker(issKP, certExpire, issuerName, snAllocator);
    }
}
