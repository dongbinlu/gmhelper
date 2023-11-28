package org.zz.gmhelper.cert.test;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class X509Cert {

    @Test
    public void testX509Cert() throws Exception {
        String rootCert = "MIIChDCCAi+gAwIBAgIBATAMBggqgRzPVQGDdQUAMIGfMSowKAYDVQQDDCFMTSBTTTIgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkxIDAeBgkqhkiG9w0BCQEMEWxtQGxvbmdtYWkuY29tLmNuMQwwCgYDVQQLDANKSVQxEDAOBgNVBAoMB2xvbmdtYWkxEDAOBgNVBAcMB0JlaWppbmcxEDAOBgNVBAgMB0JlaWppbmcxCzAJBgNVBAYMAkNOMB4XDTE1MDkxNzA0MDAwMFoXDTM1MDkxNzA0MDAwMFowgZ8xKjAoBgNVBAMMIUxNIFNNMiBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eTEgMB4GCSqGSIb3DQEJAQwRbG1AbG9uZ21haS5jb20uY24xDDAKBgNVBAsMA0pJVDEQMA4GA1UECgwHbG9uZ21haTEQMA4GA1UEBwwHQmVpamluZzEQMA4GA1UECAwHQmVpamluZzELMAkGA1UEBgwCQ04wUjAMBggqgRzPVQGDdQUAA0IABNSYxIYaJYeeGpUAXoYCdXT5m6UteB5imgosEwc8bpwFBIUKOMBXzQfcn5tPeXfH/fdVd8jKvFQVkFbrL34h1rmjXzBdMAsGA1UdDwQEAwIHgDAhBgNVHREEGjAYgRZsb25nbWFpQGxvbmdtYWkuY29tLmNuMCsGA1UdHwQkMCIwIKAeoByGGmh0dHA6Ly8xMjcuMC4wLjEvdGVzdGNhbXMvMAwGCCqBHM9VAYN1BQADQQDMi2XEQhrgcDK7yIulU4rBM7mEp+a/N1EypvjA0/ZGoW4M80+OnDqCHFEhVwVtX/SMCJ6YHPvnNiQF7Lt/tCGs";

        InputStream inStream = new ByteArrayInputStream(Base64.decode(rootCert));

        try (ASN1InputStream aIn = new ASN1InputStream(inStream)) {
            ASN1Sequence seq = (org.bouncycastle.asn1.ASN1Sequence) aIn.readObject();

            X509CertificateStructure cert = new X509CertificateStructure(seq);

            System.out.println("证书版本:\t" + cert.getVersion());
            System.out.println("序列号:\t\t" + cert.getSerialNumber().getValue().toString(16));
            System.out.println("签发者:\t\t" + cert.getIssuer());
            System.out.println("开始时间:\t" + cert.getStartDate().getTime());
            System.out.println("结束时间:\t" + cert.getEndDate().getTime());
            System.out.println("主体名:\t\t" + cert.getSubject());
            System.out.print("签名值:\t\t" + cert.getSignature());
        }
    }

}