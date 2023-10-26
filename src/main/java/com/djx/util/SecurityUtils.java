package com.djx.util;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.io.IoUtil;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * TODO description
 *
 * @author qiudw
 * @date 5/18/2023
 */
public class SecurityUtils {

	public static PublicKey loadPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		try (InputStream inputStream = SecurityUtils.class.getClassLoader().getResourceAsStream("public.key")) {
			assert inputStream != null;
			byte[] publicKey = IoUtil.readBytes(inputStream);
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec encodeRule = new X509EncodedKeySpec(Base64.decode(publicKey));
			return keyfactory.generatePublic(encodeRule);
		}
	}
	public static PrivateKey loadPrivateKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		try (InputStream inputStream = SecurityUtils.class.getClassLoader().getResourceAsStream("private.key")) {
			assert inputStream != null;
			byte[] privateKey = IoUtil.readBytes(inputStream);
			KeyFactory keyfactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec encodeRule = new PKCS8EncodedKeySpec(Base64.decode(privateKey));
			return keyfactory.generatePrivate(encodeRule);
		}
	}

}
