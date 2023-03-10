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
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Main {

    private final static String privateKeyPassword = "123456789";
    private final static String keystoreCertAlias = "f22c0321-1a9a-4877-9295-73092bb9aa94";

    public static void main( String[] args )
    {
        byte[] docBytes = null;
        byte[] signature = null;

        Security.addProvider(new BouncyCastleProvider());

        Main main = new Main();

        InputStream docFile = main.getResourceStream("arquivos/doc.txt");

        try {
            docBytes = docFile.readAllBytes();
            docFile.close();
        } catch (IOException e) {
            System.out.println(String.format("Could not read doc.txt due to the error: %s\nSkipping all etapas...\nTerminating program.\n\n", e.getMessage()));
            System.exit(1);
        }

        try {
            // Etapa 1: Resumo criptográfico
            etapa1(docBytes);
            System.out.println("Etapa 1 success!");
        } catch (EtapaDesafioException e) {
            System.out.println(String.format("Etapa 1 error: %s\nEtapa 1 failed.\n\n", e.getMessage()));
        }

        InputStream pkcs12InputStream = main.getResourceStream("pkcs12/desafio.p12");

        try {
            // Etapa 2: Realizar uma assinatura digital
            signature = etapa2(docBytes, pkcs12InputStream, keystoreCertAlias, privateKeyPassword.toCharArray());
            System.out.println("Etapa 2 success!");
        } catch (EtapaDesafioException e) {
            System.out.println(String.format("Etapa 2 error: %s\nEtapa 2 failed. Skipping Etapa 3 due to Etapa 2 error...\nTerminating program.\n\n", e.getMessage()));
            System.exit(1);
        }

        try {
            // Etapa 3: Verificar a assinatura gerada
            etapa3(signature);
            System.out.println("Etapa 3 success!");
        } catch (EtapaDesafioException e) {
            System.out.println(String.format("Etapa 3 error: %s\nEtapa 3 failed.\n\n", e.getMessage()));
        }
    }

    private static void etapa1(byte[] data) throws EtapaDesafioException {

        byte[] digest = SigningUtilities.digestData(data);
        String digestHexString = Hex.toHexString(digest);

        try {
            BufferedWriter writer = new BufferedWriter(new FileWriter("output/doc_hex_digest.txt"));
            System.out.println(digestHexString);
            writer.write(digestHexString);
            writer.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static byte[] etapa2(byte[] dataToSign, InputStream pkcs12InputStream, String keystoreCertAlias, char[] privateKeyPassword) throws EtapaDesafioException {
        SignerCertKey signerCertKey = SigningUtilities.loadCertKeyFromPKCS12(pkcs12InputStream, keystoreCertAlias, privateKeyPassword);
        X509Certificate signerCertificate = signerCertKey.getX509Certificate();
        PrivateKey signerKey = signerCertKey.getPrivateKey();
        byte[] signature;

        try {
            pkcs12InputStream.close();
        } catch (IOException e) {
            throw new EtapaDesafioException("An error occurred when trying to close PKCS12 input stream", e);
        }

//        signerCertificate.checkValidity();
        System.out.println(signerKey.toString());
        System.out.println(signerCertificate.toString());
        try {
            signature = SigningUtilities.signData(dataToSign, signerKey, signerCertificate);
        } catch (OperatorCreationException e) {
            throw new EtapaDesafioException("Internal error during signature operation.", e);
        } catch (CertificateEncodingException e) {
            throw new EtapaDesafioException("An error occurred when trying encode the signing certificate. Verify if " +
                    "the certificate file is correct.", e);
        } catch (SigningException e) {
            throw new EtapaDesafioException("An error occurred while performing the signature.", e);
        }

        try {
            FileOutputStream outputStream = new FileOutputStream("output/doc_signature.p7s");
            outputStream.write(signature);
            outputStream.close();
            return signature;

        } catch (FileNotFoundException e) {
            throw new EtapaDesafioException("Could not create signature output file.", e);
        } catch (IOException e) {
            throw new EtapaDesafioException("An error occurred when trying to close PKCS12 input stream", e);
        }
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

    private InputStream getResourceStream(String resourceName) {
        InputStream resourceInputStream = getClass().getClassLoader().getResourceAsStream(resourceName);
        return resourceInputStream;
    }
}
