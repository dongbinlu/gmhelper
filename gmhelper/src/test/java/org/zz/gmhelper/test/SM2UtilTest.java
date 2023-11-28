package org.zz.gmhelper.test;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.engines.SM2Engine.Mode;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;
import org.junit.Assert;
import org.junit.Test;
import org.zz.gmhelper.BCECUtil;
import org.zz.gmhelper.SM2Cipher;
import org.zz.gmhelper.SM2Util;
import org.zz.gmhelper.cert.SM2CertUtil;
import org.zz.gmhelper.test.util.FileUtil;
import sun.misc.BASE64Decoder;

import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;

public class SM2UtilTest extends GMBaseTest {

    @Test
    public void testSM2KeyGen2() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                    + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Y Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }


    @Test
    public void testGenerateBCECKeyPair() {
        try {
            KeyPair keyPair = SM2Util.generateKeyPair();
            ECPrivateKeyParameters priKey = BCECUtil.convertPrivateKeyToParameters((BCECPrivateKey) keyPair.getPrivate());
            ECPublicKeyParameters pubKey = BCECUtil.convertPublicKeyToParameters((BCECPublicKey) keyPair.getPublic());

            byte[] sign = SM2Util.sign(priKey, WITH_ID, SRC_DATA);
            boolean flag = SM2Util.verify(pubKey, WITH_ID, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }

            sign = SM2Util.sign(priKey, SRC_DATA);
            flag = SM2Util.verify(pubKey, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testEncryptAndDecrypt() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();
            System.out.println("Pri Hex:"
                    + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Y Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

            byte[] encryptedData = SM2Util.encrypt(pubKey, SRC_DATA_24B);
            System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(encryptedData).toUpperCase());
            byte[] decryptedData = SM2Util.decrypt(priKey, encryptedData);
            System.out.println("SM2 decrypt result:\n" + ByteUtils.toHexString(decryptedData).toUpperCase());
            if (!Arrays.equals(decryptedData, SRC_DATA_24B)) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testEncryptAndDecrypt_C1C2C3() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                    + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Y Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

            byte[] encryptedData = SM2Util.encrypt(Mode.C1C2C3, pubKey, SRC_DATA_48B);
            System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(encryptedData));
            byte[] decryptedData = SM2Util.decrypt(Mode.C1C2C3, priKey, encryptedData);
            System.out.println("SM2 decrypt result:\n" + ByteUtils.toHexString(decryptedData));
            if (!Arrays.equals(decryptedData, SRC_DATA_48B)) {
                Assert.fail();
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testParseSM2Cipher() throws Exception {
        String hexStr = "042A543BF7F1E2326BDC62323B94AE5DFE9699F0C000C6D5571850F65227F6949BCD151AA2312543F65D76686DE01AA2E5E92F2BA607F3730202BD69C8205229F5A4FC6FC518D21D3271A158FD91EC8E9232400ED2BFCC957BA8AFFD96DF091BAA6410FB30211EC0954455A76756287E3DDBCE0F853F985C60";

        SM2Cipher sm2Cipher = SM2Util.parseSM2Cipher(ByteUtils.fromHexString(hexStr));

    }


    @Test
    public void testEncodeSM2CipherToDER() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] encryptedData = SM2Util.encrypt(pubKey, SRC_DATA);
            System.out.println("SM2 encrypt result:\n" + ByteUtils.toHexString(encryptedData));
            byte[] derCipher = SM2Util.encodeSM2CipherToDER(encryptedData);
            System.out.println("SM2 encode derCipher result:\n" + ByteUtils.toHexString(derCipher));
            FileUtil.writeFile("target/derCipher.dat", derCipher);
            byte[] decodeDerCipher = SM2Util.decodeDERSM2Cipher(derCipher);
            System.out.println("SM2 decode derCipher result:\n" + ByteUtils.toHexString(decodeDerCipher));

            byte[] decryptedData = SM2Util.decrypt(priKey, SM2Util.decodeDERSM2Cipher(derCipher));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }

            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testEncodeSM2CipherToDERForLoop() {
        try {
            for (int i = 0; i < 1000; ++i) {
                AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
                ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
                ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

                byte[] encryptedData = SM2Util.encrypt(pubKey, SRC_DATA);

                byte[] derCipher = SM2Util.encodeSM2CipherToDER(encryptedData);

                byte[] decryptedData = SM2Util.decrypt(priKey, SM2Util.decodeDERSM2Cipher(derCipher));
                if (!Arrays.equals(decryptedData, SRC_DATA)) {
                    Assert.fail();
                }
            }
            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testEncodeSM2CipherToDER_C1C2C3() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            byte[] encryptedData = SM2Util.encrypt(Mode.C1C2C3, pubKey, SRC_DATA);

            byte[] derCipher = SM2Util.encodeSM2CipherToDER(Mode.C1C2C3, encryptedData);
            FileUtil.writeFile("target/derCipher_c1c2c3.dat", derCipher);

            byte[] decryptedData = SM2Util.decrypt(Mode.C1C2C3, priKey, SM2Util.decodeDERSM2Cipher(Mode.C1C2C3, derCipher));
            if (!Arrays.equals(decryptedData, SRC_DATA)) {
                Assert.fail();
            }

            Assert.assertTrue(true);
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testSignAndVerify() {
        try {
            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            System.out.println("Pri Hex:"
                    + ByteUtils.toHexString(priKey.getD().toByteArray()).toUpperCase());
            System.out.println("Pub X Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineXCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Y Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getAffineYCoord().getEncoded()).toUpperCase());
            System.out.println("Pub Point Hex:"
                    + ByteUtils.toHexString(pubKey.getQ().getEncoded(false)).toUpperCase());

            byte[] sign = SM2Util.sign(priKey, WITH_ID, SRC_DATA);
            System.out.println("SM2 sign with withId result:\n" + ByteUtils.toHexString(sign));
            byte[] rawSign = SM2Util.decodeDERSM2Sign(sign);
            sign = SM2Util.encodeSM2SignToDER(rawSign);
            System.out.println("SM2 sign with withId result:\n" + ByteUtils.toHexString(sign));
            boolean flag = SM2Util.verify(pubKey, WITH_ID, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }

            sign = SM2Util.sign(priKey, SRC_DATA);
            System.out.println("SM2 sign without withId result:\n" + ByteUtils.toHexString(sign));
            flag = SM2Util.verify(pubKey, SRC_DATA, sign);
            if (!flag) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    @Test
    public void testKeyPairEncoding() {
        try {

            AsymmetricCipherKeyPair keyPair = SM2Util.generateKeyPairParameter();
            ECPrivateKeyParameters priKey = (ECPrivateKeyParameters) keyPair.getPrivate();
            ECPublicKeyParameters pubKey = (ECPublicKeyParameters) keyPair.getPublic();

            // 将私钥转换成der编码
            byte[] priKeyPkcs8Der = BCECUtil.convertECPrivateKeyToPKCS8(priKey, pubKey);
            System.out.println("private key pkcs8 der length:" + priKeyPkcs8Der.length);
            System.out.println("private key pkcs8 der:" + ByteUtils.toHexString(priKeyPkcs8Der));
            FileUtil.writeFile("target/ec.pkcs8.pri.der", priKeyPkcs8Der);

            // 将私钥der编码转成pem编码
            String priKeyPkcs8Pem = BCECUtil.convertECPrivateKeyPKCS8ToPEM(priKeyPkcs8Der);
            FileUtil.writeFile("target/ec.pkcs8.pri.pem", priKeyPkcs8Pem.getBytes("UTF-8"));

            // 将私钥pem编码转成der编码
            byte[] priKeyFromPem = BCECUtil.convertECPrivateKeyPEMToPKCS8(priKeyPkcs8Pem);
            if (!Arrays.equals(priKeyFromPem, priKeyPkcs8Der)) {
                throw new Exception("priKeyFromPem != priKeyPkcs8Der");
            }
            //注意 私钥需要通过der编码转pem编码，不能直接转pem编码，防止私钥格式出错

            // 将der编码私钥转换为BCECPrivateKey对象
            BCECPrivateKey newPriKey = BCECUtil.convertPKCS8ToECPrivateKey(priKeyPkcs8Der);


            // 将私钥装换为SEC1格式
            byte[] priKeyPkcs1Der = BCECUtil.convertECPrivateKeyToSEC1(priKey, pubKey);
            System.out.println("private key pkcs1 der length:" + priKeyPkcs1Der.length);
            System.out.println("private key pkcs1 der:" + ByteUtils.toHexString(priKeyPkcs1Der));
            FileUtil.writeFile("target/ec.pkcs1.pri", priKeyPkcs1Der);
            // -----------------------------------------------------------------------------------------------------
            // 将公钥转成x509 der编码
            byte[] pubKeyX509Der = BCECUtil.convertECPublicKeyToX509(pubKey);
            System.out.println("public key der length:" + pubKeyX509Der.length);
            System.out.println("public key der:" + ByteUtils.toHexString(pubKeyX509Der));
            FileUtil.writeFile("target/ec.x509.pub.der", pubKeyX509Der);

            // 将公钥从x509 der编码转pem编码
            String pubKeyX509Pem = BCECUtil.convertECPublicKeyX509ToPEM(pubKeyX509Der);
            FileUtil.writeFile("target/ec.x509.pub.pem", pubKeyX509Pem.getBytes("UTF-8"));

            // 将公钥从pem编码转x509der编码
            byte[] pubKeyFromPem = BCECUtil.convertECPublicKeyPEMToX509(pubKeyX509Pem);
            if (!Arrays.equals(pubKeyFromPem, pubKeyX509Der)) {
                throw new Exception("pubKeyFromPem != pubKeyX509Der");
            }


        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }

    /**
     * 将证书转换为pem编码或der编码
     * 注意：
     * 证书转换为pem编码或der编码和公钥转pem编码或der编码不一样，一个是转证书，一个是转公钥
     *
     * @throws Exception
     */
    @Test
    public void testCertToPem() throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        String signCert = "MIIB6DCCAY6gAwIBAgICAKIwCgYIKoEcz1UBg3UwTTEcMBoGA1UEAwwTU00yIEludGVybWVkaWF0ZSBDQTEPMA0GA1UECwwGU0hVRFVOMQ8wDQYDVQQKDAZTSFVEVU4xCzAJBgNVBAYTAkNOMB4XDTIzMTEyMTAyNDU1OVoXDTI2MTEyMDAyNDU1OVowPTELMAkGA1UEBhMCQ04xDzANBgNVBAoMBlNodUR1bjEMMAoGA1UECwwDSFNNMQ8wDQYDVQQDDAZzaHVkdW4wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARtuUvOuJaHlmtdqDKvQpktgjNQpg6QKN1Ywz1GVaPHIrAugV/mXbskp4jtZiG5sZTmXJpLqLFm7ce/vTmM2e1Po24wbDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBRwTsNhF5U4wLKCfE5PEZhyW2wNSzAfBgNVHSMEGDAWgBSgIexp7furRzBuPOa4xoG/LUJPUzAOBgNVHQ8BAf8EBAMCBDAwDAYDVR0lAQH/BAIwADAKBggqgRzPVQGDdQNIADBFAiAYJCI0UZACwJrCb0Y0sqs0UwMOBUZ/lDtKffJ8D9IHpgIhALSnmQVB4Q+80ksNP2vz98etV34QrvOBm5pVLVOG+7mi";
        byte[] signBytes = (new BASE64Decoder()).decodeBuffer(signCert);
        X509Certificate x509Certificate = SM2CertUtil.getX509Certificate(signBytes);
        // 将证书转换为PEM编码
        try (FileWriter fileWriter = new FileWriter("target/certificate.pem");
             JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter)) {

            pemWriter.writeObject(x509Certificate);
        }

        // 将证书转换为DER编码
        try (FileOutputStream fos = new FileOutputStream("target/certificate.der")) {
            byte[] derCert = x509Certificate.getEncoded();
            fos.write(derCert);
        }

    }

    // 密钥恢复
    @Test
    public void testSM2KeyRecovery() {
        try {
            String priHex = "5DD701828C424B84C5D56770ECF7C4FE882E654CAC53C7CC89A66B1709068B9D";
            String xHex = "FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913";
            String yHex = "F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956";
            String encodedPubHex = "04FF6712D3A7FC0D1B9E01FF471A87EA87525E47C7775039D19304E554DEFE0913F632025F692776D4C13470ECA36AC85D560E794E1BCCF53D82C015988E0EB956";
            String signHex = "30450220213C6CD6EBD6A4D5C2D0AB38E29D441836D1457A8118D34864C247D727831962022100D9248480342AC8513CCDF0F89A2250DC8F6EB4F2471E144E9A812E0AF497F801";
            byte[] signBytes = ByteUtils.fromHexString(signHex);
            byte[] src = ByteUtils.fromHexString("0102030405060708010203040506070801020304050607080102030405060708");
            byte[] withId = ByteUtils.fromHexString("31323334353637383132333435363738");

            ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
                    new BigInteger(ByteUtils.fromHexString(priHex)), SM2Util.DOMAIN_PARAMS);
            ECPublicKeyParameters pubKey = BCECUtil.createECPublicKeyParameters(xHex, yHex, SM2Util.CURVE, SM2Util.DOMAIN_PARAMS);

            if (!SM2Util.verify(pubKey, src, signBytes)) {
                Assert.fail("verify failed");
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            Assert.fail();
        }
    }


}
