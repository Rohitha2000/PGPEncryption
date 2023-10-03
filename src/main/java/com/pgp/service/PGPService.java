package com.pgp.service;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.List;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class PGPService {
	
	public static final Logger log= LoggerFactory.getLogger(PGPService.class);

	
	public void encryptWavFiles(List<MultipartFile> files) throws Exception {
		
		PGPPublicKey publickey= extractPGPPublicKey("src/main/resources/public.pgp");
		 Path encryptedDir = Path.of("src/main/java/encrypted");
		 Files.createDirectories(encryptedDir);
		  for (MultipartFile file : files) {
              if (!file.isEmpty()) {
                  // Encrypt the file and save it in the 'encrypted' directory
                  String encryptfileName = file.getOriginalFilename().replace(".wav", ".pgp");
                  Path encryptedFilePath = encryptedDir.resolve(encryptfileName);
                  

                  byte[] encryptedStream= encryption(encryptfileName, file, publickey);
                  Files.write(encryptedFilePath, encryptedStream);
                 
              }
          }
	}
	
	
	public byte[] encryption(String outputFilePath, MultipartFile file , PGPPublicKey publicKey) throws Exception {
		 ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
		//OutputStream out1 = new FileOutputStream(encryptedData);
		OutputStream  out1 = new ArmoredOutputStream(encryptedData);
        
        byte[] buffer = new byte[1024];
        int len;
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(true)
                        .setSecureRandom(new SecureRandom()));
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setSecureRandom(new SecureRandom()));
        OutputStream encOut = encGen.open(out1, new byte[1024]);
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        OutputStream pOut = lData.open(encOut, PGPLiteralData.BINARY, new File(file.getOriginalFilename()));
        InputStream in = file.getInputStream();

        try {
            while ((len = in.read(buffer)) > 0) {
                pOut.write(buffer, 0, len);
            }
            
        } 
        catch(Exception e ){
        	 log.info(" ** Failed to Encrypt the file : "+ file.getOriginalFilename());
        	throw new Exception("Failed to Encrypt the file");
        	
        }finally {
            // Close the streams in reverse order
            in.close();
            pOut.close();
            lData.close();
            encOut.close();
            encGen.close();
            out1.close();
            
        }
        log.info(" ** File Succcessfully encrypted to : "+ outputFilePath);
        return encryptedData.toByteArray();
       
	}
	
	
	
	public static PGPPublicKey extractPGPPublicKey(String publicKeyFilePath) throws IOException, PGPException {
    	InputStream in = new FileInputStream(publicKeyFilePath);
        ArmoredInputStream armoredInputStream = new ArmoredInputStream(in);
        try  {

            // Create a key ring collection from the armored input stream
        	 PGPObjectFactory pgpFactory = new PGPObjectFactory(armoredInputStream, new JcaKeyFingerprintCalculator());
				
				

             // Assume the public key is at the first position in the file
             PGPPublicKeyRing publicKeyRing = (PGPPublicKeyRing) pgpFactory.nextObject();

             // Get the public key from the key ring
             PGPPublicKey publicKey = publicKeyRing.getPublicKey();

             return publicKey;
        }finally {
			
		}
    
    }
}
