package org.example;

import org.apache.commons.io.FileUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Hex;
import org.example.exceptions.EtapaDesafioException;
import org.example.exceptions.SignatureVerificationException;
import org.example.exceptions.SigningException;

import java.io.*;
import java.io.FileOutputStream;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Main {

    private final static String privateKeyPassword = "Bry123";
    private final static String keystoreCertAlias = "4711a752-3249-4207-b039-d2bbeb7df38c";

    public static void main( String[] args )
    {
        byte[] signature = null;

        Security.addProvider(new BouncyCastleProvider());

        Main main = new Main();

        byte[] docBytes = null;
        byte[] pkcs12Bytes = null;

        try {
            docBytes = main.getResourceBytes("arquivos/doc.txt");
            pkcs12Bytes = main.getResourceBytes("pkcs12/desafio.p12");
        } catch (IOException e) {
            System.exit(1);
        }

//        try {
//            String docFileString = FileUtils.readFileToString(docFile, Charset.defaultCharset());
//            System.out.println(docFileString);
//
//            File digestOutputFile = FileUtils.getFile("output/doc_hex_digest.txt");
//            FileUtils.writeStringToFile(digestOutputFile, "Teste", Charset.defaultCharset());
//        } catch (Exception e) {
//            e.printStackTrace();
//        }

        try {
            // Etapa 1: Resumo criptográfico
            etapa1(docBytes);
            System.out.println("Etapa 1 success!");
        } catch (EtapaDesafioException e) {
            System.out.printf("Etapa 1 error: %s\nEtapa 1 failed.\n\n%n", e.getMessage());
        }

        try {
            // Etapa 2: Realizar uma assinatura digital
            signature = etapa2(docBytes, pkcs12Bytes, keystoreCertAlias, privateKeyPassword.toCharArray());
            System.out.println("Etapa 2 success!");
        } catch (EtapaDesafioException e) {
            System.out.printf("Etapa 2 error: %s\nEtapa 2 failed. Skipping Etapa 3 due to Etapa 2 error...\nTerminating program.\n\n%n", e.getMessage());
            System.exit(1);
        }

        try {
            // Etapa 3: Verificar a assinatura gerada
            etapa3(signature);
            System.out.println("Etapa 3 success!");
        } catch (EtapaDesafioException e) {
            System.out.printf("Etapa 3 error: %s\nEtapa 3 failed.\n\n%n", e.getMessage());
        }
    }

    private static void etapa1(byte[] docBytes) throws EtapaDesafioException {

        byte[] digest;
        try {
            digest = SigningUtilities.digestData(docBytes);
        } catch (IOException e) {
            throw new EtapaDesafioException("Could read the document's byte.", e);
        }

        String digestHexString = Hex.toHexString(digest);

        File digestOutputFile = FileUtils.getFile("output/doc_hex_digest.txt");

        try {
            FileUtils.writeStringToFile(digestOutputFile, digestHexString, Charset.defaultCharset());
        } catch (IOException e) {
            throw new EtapaDesafioException("An error occured while writing the digest hexstring to the file.", e);
        }
    }

    private static byte[] etapa2(byte[] fileBytes, byte[] pkcs12Bytes, String keystoreCertAlias, char[] privateKeyPassword) throws EtapaDesafioException {
        SignerCertKey signerCertKey;
        try {
            signerCertKey = SigningUtilities.loadCertKeyFromPKCS12(pkcs12Bytes, keystoreCertAlias, privateKeyPassword);
        } catch (IOException e) {
            throw new EtapaDesafioException("Could not load keystore data. Check if the provided file is correct and if" +
                    "password is correct.", e);
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new EtapaDesafioException("An internal error occurred while loading the PKCS#12 keystore.", e);
        } catch (CertificateException e) {
            throw new EtapaDesafioException("The certificate of the provided keystore could not be loaded.", e);
        } catch (UnrecoverableKeyException e) {
            throw new EtapaDesafioException("The private key of the provided keystore could not be recovered. The password could be incorrect.", e);
        }

        X509Certificate signerCertificate = signerCertKey.getX509Certificate();
        PrivateKey signerKey = signerCertKey.getPrivateKey();
        byte[] signature;

//        System.out.println(signerKey.toString());
//        System.out.println(signerCertificate.toString());
        try {
            signature = SigningUtilities.signData(fileBytes, signerKey, signerCertificate);
        } catch (OperatorCreationException e) {
            throw new EtapaDesafioException("Internal error during signature operation.", e);
        } catch (CertificateEncodingException e) {
            throw new EtapaDesafioException("An error occurred when trying encode the signing certificate. Verify if " +
                    "the certificate file is correct.", e);
        } catch (SigningException e) {
            throw new EtapaDesafioException("An error occurred while performing the signature.", e);
        }

        try {
            File docSignatureFile = FileUtils.getFile("output/doc_signature.p7s");
            try (FileOutputStream docSignatureOutputStream = FileUtils.openOutputStream(docSignatureFile)) {
                docSignatureOutputStream.write(signature);
            } } catch (IOException e) {
            throw new EtapaDesafioException("An error occurred while writing to signature file output stream.", e);
        }

        return signature;
    }

    private static void etapa3(byte[] signature) throws EtapaDesafioException {
        try {
            SigningUtilities.verifySignature(signature);
        } catch (OperatorCreationException e) {
            throw new EtapaDesafioException("Internal error during signature operation.", e);
        } catch (CertificateException e) {
            throw new EtapaDesafioException("Certificate error. Verify if the certificate is correct.", e);
        } catch (IOException | CMSException e) {
            throw new EtapaDesafioException("An error occurred while processing the signed data. Verify if the data" +
                    "is correct", e);
        } catch (SignatureVerificationException e) {
            throw new EtapaDesafioException(e.getMessage(), e);
        }
    }

    private byte[] getResourceBytes(String resourceName) throws IOException {
        try (InputStream resourceStream = getClass().getClassLoader().getResourceAsStream(resourceName)) {
            return resourceStream.readAllBytes();
        }
    }
}
