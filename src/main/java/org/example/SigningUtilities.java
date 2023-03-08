package org.example;

import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;

public class SigningUtilities {
    private final static String privateKeyPassword = "123456789";
    private final static String keystoreCertAlias = "f22c0321-1a9a-4877-9295-73092bb9aa94";

    public static void main( String[] args ) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        SigningUtilities signingUtils = new SigningUtilities();

        InputStream docFile = signingUtils.getResourceStream("arquivos/doc.txt");
        byte[] docBytes = docFile.readAllBytes();
        docFile.close();

        // Etapa 1: Resumo criptográfico
        etapa1(docBytes);

        // Etapa 2: Realizar uma assinatura digital
        InputStream pkcs12InputStream = signingUtils.getResourceStream("pkcs12/desafio.p12");
        byte[] signature = etapa2(docBytes, pkcs12InputStream);

        // Etapa 3: Verificar a assinatura gerada
        etapa3(signature);
    }

//	private String getResource(String resourceName) {
//		String resourcePathString = getClass().getClassLoader().getResource(resourceName).getPath();
//		System.out.println(resourcePathString);
//		return resourcePathString;
//	}

    private InputStream getResourceStream(String resourceName) {
        InputStream resourceInputStream = getClass().getClassLoader().getResourceAsStream(resourceName);
        return resourceInputStream;
    }


    public static void etapa1(byte[] data) {

        byte[] digest = SigningUtilities.digestData(data);
        String digestHexString = Hex.toHexString(digest);

        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter("/home/jpadn/teste.csv"));
            System.out.println(digestHexString);
            writer.write(digestHexString);
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static SignerCertKey loadCertKeyFromPKCS12(InputStream pkcs12InputStream, String alias, char[] password) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(pkcs12InputStream, password);

            // Recuperando a chave privada e o certificado da entidade assinante
            PrivateKey signerKey = (PrivateKey) keyStore.getKey(alias, password);
            X509Certificate signerCertificate = (X509Certificate) keyStore.getCertificate(alias);

            return new SignerCertKey(signerCertificate, signerKey);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static byte[] etapa2(byte[] dataToSign, InputStream pkcs12InputStream) {

        PrivateKey signerKey;
        X509Certificate signerCertificate;

        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(pkcs12InputStream, privateKeyPassword.toCharArray());

            // Recuperando a chave privada e o certificado da entidade assinante
            signerKey = (PrivateKey) keyStore.getKey(keystoreCertAlias, privateKeyPassword.toCharArray());
            signerCertificate = (X509Certificate) keyStore.getCertificate(keystoreCertAlias);

//            signerCertificate.checkValidity();
            System.out.println(signerKey.toString());
            System.out.println(signerCertificate.toString());
            pkcs12InputStream.close();

            byte[] signature = SigningUtilities.signDataDesafio(dataToSign, signerKey, signerCertificate);

            FileOutputStream outputStream = new FileOutputStream("/home/jpadn/doc_signature.p7s");
            outputStream.write(signature);
            outputStream.close();
            return signature;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }

    public static void etapa3(byte[] signature) {
        SigningUtilities.verifySignature(signature);
    }

    public static byte[] digestData(byte[] data) {

        SHA256Digest messageDigest = new SHA256Digest();

        byte[] digested = new byte[messageDigest.getDigestSize()];

        messageDigest.update(data, 0, data.length);
        messageDigest.doFinal(digested, 0);

        return digested;
    }

    public static byte[] signData(byte[] data, X509Certificate signingCertificate, PrivateKey signingKey) throws Exception {

        byte[] signedMessage = null;

        List<X509Certificate> certList= new ArrayList<X509Certificate>();
        certList.add(signingCertificate);
        Store certs = new JcaCertStore(certList);

        CMSTypedData cmsData = new CMSProcessableByteArray(data);

        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();

        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(signingKey);
            cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(contentSigner, signingCertificate));
            cmsGenerator.addCertificates(certs);

            // Signing procedure
            CMSSignedData cms = cmsGenerator.generate(cmsData, true);
            signedMessage = cms.getEncoded();

        } catch (Exception e) {
            e.printStackTrace();
        }
        return signedMessage;
    }


    public static byte[] signDataDesafio(byte[] data, PrivateKey signerKey, X509Certificate signerCertificate) {
        List<X509Certificate> certList= new ArrayList<X509Certificate>();
        certList.add(signerCertificate);

        CMSTypedData cmsData = new CMSProcessableByteArray(data);
        CMSSignedDataGenerator cmsGenerator = new CMSSignedDataGenerator();
        byte[] signature;


        // Operações relacionadas ao CMSSignedDataGenerator
        try {
            ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(signerKey);
            cmsGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(contentSigner, signerCertificate));

            Store certs = new JcaCertStore(certList);
            cmsGenerator.addCertificates(certs);

            // Gerando a assinatura de acordo com padrão CMS
            CMSSignedData cms = cmsGenerator.generate(cmsData, true);

            // Obtendo representação ASN.1 da assinatura
            signature = cms.getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
            signature = null;
        }

        return signature;
    }

//    public static boolean verifySignatureDesafio(byte[] signedData, byte[] signature) {
//
//    	SignerInformation
//
//
//    	return false;
//    }


    public static boolean verifySignature(byte[] data) {

        X509Certificate signCert = null;
        CMSSignedData cmsSignedData = null;
        boolean validSignature;

        // Convertendo signedData para ASN1InputStream
        ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
        ASN1InputStream asnInputStream = new ASN1InputStream(inputStream);

        try {
            cmsSignedData = new CMSSignedData(ContentInfo.getInstance(asnInputStream.readObject()));
        } catch (Exception e) {

        }

        // Obtendo todos os assinantes da mensagem assinada cmsSignedData
        SignerInformationStore signers = cmsSignedData.getSignerInfos();

        // Como já espera-se que seja apenas um assinante, não vamos iterar a coleção
        SignerInformation signer = signers.getSigners().iterator().next();

        Collection<X509CertificateHolder> certCollection = cmsSignedData.getCertificates().getMatches(signer.getSID());

        X509CertificateHolder certHolder = certCollection.iterator().next();

        try {
            validSignature = signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certHolder));
        } catch (Exception e) {
            e.printStackTrace();
            validSignature = false;
        }

        return validSignature;
    }
}