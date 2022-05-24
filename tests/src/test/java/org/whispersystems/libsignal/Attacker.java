package org.whispersystems.libsignal;

import org.whispersystems.libsignal.logging.Log;
import org.whispersystems.libsignal.state.SessionState;
import org.whispersystems.libsignal.ratchet.MessageKeys;
import org.whispersystems.libsignal.protocol.CiphertextMessage;
import org.whispersystems.libsignal.ratchet.ChainKey;
import org.whispersystems.libsignal.ecc.ECPublicKey;
import org.whispersystems.libsignal.protocol.SignalMessage;


import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import static org.whispersystems.libsignal.protocol.AuthStepProtos.AuthSet;

public class Attacker {
    private SessionState sessionState;

    public Attacker(SessionCipherAuthStep victim) {
        sessionState = victim.leakSessionState();
    }

    public CiphertextMessage encrypt(byte[] paddedMessage) throws UntrustedIdentityException {
      ChainKey      chainKey        = sessionState.getSenderChainKey();
      MessageKeys   messageKeys     = chainKey.getMessageKeys();
      ECPublicKey   senderEphemeral = sessionState.getSenderRatchetKey();
      int           previousCounter = sessionState.getPreviousCounter();
      int           sessionVersion  = sessionState.getSessionVersion();

      AuthSet authInfo = AuthSet.newBuilder()
                                .setStep(0)
                                .build();
      ByteArrayOutputStream augmentedPtxt = new ByteArrayOutputStream();
      byte[] authInfoBytes = authInfo.toByteArray();
      byte[] length = ByteBuffer.allocate(4)
                                .order(ByteOrder.LITTLE_ENDIAN)
                                .putInt(authInfoBytes.length)
                                .array();
      
      try {
        augmentedPtxt.write(length);
        augmentedPtxt.write(authInfoBytes);
        augmentedPtxt.write(paddedMessage);
      } catch(IOException e) {
        Log.w("SessionRecordV2", e);
      }

      byte[]            ciphertextBody    = getCiphertext(messageKeys, augmentedPtxt.toByteArray());
      CiphertextMessage ciphertextMessage = new SignalMessage(sessionVersion, messageKeys.getMacKey(),
                                                              senderEphemeral, chainKey.getIndex(),
                                                              previousCounter, ciphertextBody,
                                                              sessionState.getLocalIdentityKey(),
                                                              sessionState.getRemoteIdentityKey());
      return ciphertextMessage;
    }

    private byte[] getCiphertext(MessageKeys messageKeys, byte[] plaintext) {
        try {
          Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, messageKeys.getCipherKey(), messageKeys.getIv());
          return cipher.doFinal(plaintext);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
          throw new AssertionError(e);
        }
    }

    private Cipher getCipher(int mode, SecretKeySpec key, IvParameterSpec iv) {
        try {
          Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
          cipher.init(mode, key, iv);
          return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | java.security.InvalidKeyException |
                 InvalidAlgorithmParameterException e)
        {
          throw new AssertionError(e);
        }
    }
}
