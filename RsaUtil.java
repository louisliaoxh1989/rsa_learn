
package cn.felord.spring.security.rsa;

import com.fasterxml.jackson.databind.ser.Serializers;
import org.bouncycastle.jcajce.provider.asymmetric.RSA;
import org.bouncycastle.util.test.FixedSecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class RsaUtil {

    public static final int RSA_MODULUS_LEN = 128;
    public static final int RSA_P_LEN = RSA_MODULUS_LEN/2;
    public static final int RSA_Q_LEN = RSA_MODULUS_LEN/2;
    public static final int publicExponent = 65537;
    public static final String KEY_ALGORITHM_MODE_PADDING = "RSA/ECB/NoPadding"; //不填充
    public static final String KEY_ALGORITHM = "RSA"; //不填充


    private static final int MAX_ENCRYPT_BLOCK = 117;

    /**
     * RSA最大解密密文大小
     */
    private static final int MAX_DECRYPT_BLOCK = 128;


    /**
     * 发送方--私钥
     */
    private RSAPrivateKey privateKey;
    /**
     * 接收方--公钥
     */
    private RSAPublicKey publicKey;

    /**
     * 
     * @param modulus
     * @param publicExponent
     * @return
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public RSAPublicKey generationPublicKey(String modulus, String publicExponent) throws InvalidKeySpecException, NoSuchAlgorithmException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(new BigInteger(modulus),new BigInteger(publicExponent));
        return (RSAPublicKey) factory.generatePublic(rsaPublicKeySpec);
    }

    /**
     * 从hex string 生成私钥
     *
     * @param modulus
     * @param exponent
     * @return 构造好的私钥
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    public static PrivateKey generationPrivateKey(String modulus, String exponent)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        try {
            BigInteger N = new BigInteger(modulus, 16); // hex base
            BigInteger D = new BigInteger(exponent, 16); // hex base

            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(N, D);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * 获取私钥
     *
     * @param privateKey 私钥字符串
     * @return
     */
    public static PrivateKey getByPrivateKeyStr(String privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 从base64的公钥字符串转换为公钥
     * @param publicKeyStr
     * @return
     */
    public RSAPublicKey getByPublicKeyStr(String publicKeyStr) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        byte[] bytes = Base64.getDecoder().decode(publicKeyStr.getBytes(StandardCharsets.UTF_8));
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(bytes);
        return (RSAPublicKey) factory.generatePublic(x509EncodedKeySpec);

    }

   public byte[] getPublicKeyByte(RSAPublicKey rsaPublicKey){
        return rsaPublicKey.getEncoded();
   }
   public byte[] converToBytes(String data){
        return data.getBytes(StandardCharsets.UTF_8);
   }

    public  byte[] encryptByPublicKey(String data,RSAPublicKey rsaPublicKey) throws Exception{
        return  encryptByPublicKey(converToBytes(data),getPublicKeyByte(rsaPublicKey));
    }
    public  byte[] encryptByPublicKey(String data,byte[] key) throws Exception{
        return  encryptByPublicKey(converToBytes(data),key);
    }
    /**
     * 公钥加密
     * @param data 待加密的数据
     * @param key 公钥
     * @return 加密后的数据
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data,byte[] key) throws Exception{

        //实例化密钥工厂
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        //初始化公钥
        //密钥材料转换
        X509EncodedKeySpec x509KeySpec=new X509EncodedKeySpec(key);
        //产生公钥
        PublicKey pubKey=keyFactory.generatePublic(x509KeySpec);

        //数据加密
        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(data);
    }

    /**
     * 私钥加密
     * @param data 待加密数据
     * @param key 密钥
     * @return byte[] 加密数据
     * */
    public static byte[] encryptByPrivateKey(byte[] data,byte[] key) throws Exception{

        //取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec=new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        //生成私钥
        PrivateKey privateKey=keyFactory.generatePrivate(pkcs8KeySpec);
        //数据加密
        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }

    /**
     * 私钥解密
     * @param data 待解密数据
     * @param key 密钥
     * @return byte[] 解密数据
     * */
    public static byte[] decryptByPrivateKey(byte[] data,byte[] key) throws Exception{
        //取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec=new PKCS8EncodedKeySpec(key);
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        //生成私钥
        PrivateKey privateKey=keyFactory.generatePrivate(pkcs8KeySpec);
        //数据解密
        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }
    /**
     * 公钥解密
     * @param data 待解密数据
     * @param key 密钥
     * @return byte[] 解密数据
     * */
    public static byte[] decryptByPublicKey(byte[] data,byte[] key) throws Exception{

        //实例化密钥工厂
        KeyFactory keyFactory=KeyFactory.getInstance(KEY_ALGORITHM);
        //初始化公钥
        //密钥材料转换
        X509EncodedKeySpec x509KeySpec=new X509EncodedKeySpec(key);
        //产生公钥
        PublicKey pubKey=keyFactory.generatePublic(x509KeySpec);
        //数据解密
        Cipher cipher=Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        return cipher.doFinal(data);
    }
    /**
     * RSA解密
     *
     * @param data 待解密数据
     * @param privateKey 私钥
     * @return
     */
    public  String decrypt(String data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] dataBytes = Base64.getDecoder().decode(data);
        int inputLen = dataBytes.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段解密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_DECRYPT_BLOCK) {
                cache = cipher.doFinal(dataBytes, offset, MAX_DECRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(dataBytes, offset, inputLen - offset);
            }
            out.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_DECRYPT_BLOCK;
        }
        byte[] decryptedData = out.toByteArray();
        out.close();
        // 解密后的内容
        return new String(decryptedData, "UTF-8");
    }
    /**
     * 签名
     *
     * @param data 待签名数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static String sign(String data, PrivateKey privateKey) throws Exception {
        byte[] keyBytes = privateKey.getEncoded();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey key = keyFactory.generatePrivate(keySpec);
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(key);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getEncoder().encode(signature.sign()));
    }

    /**
     * 验签
     *
     * @param srcData 原始字符串
     * @param publicKey 公钥
     * @param sign 签名
     * @return 是否验签通过
     */
    public boolean verify(String srcData, PublicKey publicKey, String sign) throws Exception {
        byte[] keyBytes = publicKey.getEncoded();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initVerify(key);
        signature.update(srcData.getBytes(StandardCharsets.UTF_8));
        return signature.verify(Base64.getDecoder().decode(sign.getBytes()));
    }
    public String encrypt(RSAPublicKey publicKey,String data) throws BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        int inputLen= bytes.length;
        ByteArrayOutputStream byteArrayOutputStream=new ByteArrayOutputStream();
        int offset = 0;
        byte[] cache;
        int i = 0;
        // 对数据分段加密
        while (inputLen - offset > 0) {
            if (inputLen - offset > MAX_ENCRYPT_BLOCK) {
                cache = cipher.doFinal(data.getBytes(), offset, MAX_ENCRYPT_BLOCK);
            } else {
                cache = cipher.doFinal(data.getBytes(), offset, inputLen - offset);
            }
            byteArrayOutputStream.write(cache, 0, cache.length);
            i++;
            offset = i * MAX_ENCRYPT_BLOCK;
        }
        byte[] encryptedData = byteArrayOutputStream.toByteArray();
        byteArrayOutputStream.close();
        return Base64.getEncoder().encodeToString(encryptedData);

    }

    public Map generationKeys(int bits) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(bits);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        RSAPublicKey rsaPublicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey)keyPair.getPrivate();
        Map<String,Object> keyMap = new HashMap<String,Object>();
        keyMap.put("public",rsaPublicKey);
        keyMap.put("private",rsaPrivateKey);
        return  keyMap;
    }
    public String getPublicKeyStr(RSAPublicKey rsaPublicKey){
        return  Base64.getEncoder().encodeToString(rsaPublicKey.getEncoded());
    }
    public String getPrivateKeyStr(RSAPrivateKey rsaPrivateKey){
        return  Base64.getEncoder().encodeToString(rsaPrivateKey.getEncoded());
    }
    public static void main(String[] args){
        RsaUtil rsaUtil = new RsaUtil();

        try {
            Map<String,Object> keys=rsaUtil.generationKeys(1024);
            RSAPublicKey publicKey = (RSAPublicKey) keys.get("public");
            RSAPrivateKey privateKey = (RSAPrivateKey)keys.get("private");
            RSAPrivateCrtKey  privateCtrKey = (RSAPrivateCrtKey)privateKey;
            String publicKeyStr = rsaUtil.getPublicKeyStr(publicKey);
            String privateKeyStr = rsaUtil.getPrivateKeyStr(privateKey);
            System.out.println("公钥："+publicKeyStr);
            System.out.println("公钥加密模数:"+publicKey.getModulus()+"指数"+publicKey.getPublicExponent()+"format"+publicKey.getFormat());
            System.out.println("私钥："+privateKeyStr);
            System.out.println("私钥加密模数"+privateKey.getModulus()+"指数"+privateKey.getPrivateExponent()+"质数P"+privateCtrKey.getPrimeP());

            publicKey=rsaUtil.getByPublicKeyStr(publicKeyStr);
            System.out.println("公钥1："+publicKeyStr);
            System.out.println("公钥加密模数1:"+publicKey.getModulus()+"指数"+publicKey.getPublicExponent()+"format"+publicKey.getFormat());

            publicKey= rsaUtil.generationPublicKey("114486906202107836370757406379976980178400463163086558134023413125642308079441076538458150681078656939619518904327760697513908498089588138147725288465965129525225701081495558124234854352186083445619842057583831811873759236151602774053632007503536993908581230744346615192113896990146189044962336789949646739063","17");
            System.out.println("公钥加密模数2:"+publicKey.getModulus()+"指数"+publicKey.getPublicExponent()+"format"+publicKey.getFormat());

            String encryptData = rsaUtil.encrypt(publicKey,"liaoxiaohualiaoxiaohualiaoxiaohualiaoxiaohualiaoxiaohualiaoxiaohualiaoxiaohualiaoxiaohualiaoxiaohualiaoxiaohualiaoxiaohualiaoxiaohualiaoxiaohua");
            System.out.println(encryptData);
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

}
