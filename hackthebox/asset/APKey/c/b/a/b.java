package c.b.a;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class b
{
  public static String a(String paramString) throws Exception
  {
    char c13 = h.a().charAt(0);
    char c7 = a.a().charAt(8);
    char c8 = e.a().charAt(5);
    char c9 = i.a().charAt(4);
    char c3 = h.a().charAt(1);
    char c4 = h.a().charAt(4);
    char c14 = h.a().charAt(3);
    char c2 = h.a().charAt(3);
    char c12 = h.a().charAt(0);
    char c15 = a.a().charAt(8);
    char c11 = a.a().charAt(8);
    char c10 = i.a().charAt(0);
    char c1 = c.a().charAt(3);
    char c5 = f.a().charAt(3);
    char c6 = f.a().charAt(0);
    char c16 = c.a().charAt(0);
    Object localObject = new StringBuilder();
    ((StringBuilder)localObject).append(String.valueOf(c13));
    ((StringBuilder)localObject).append(String.valueOf(c7));
    ((StringBuilder)localObject).append(String.valueOf(c8));
    ((StringBuilder)localObject).append(String.valueOf(c9));
    ((StringBuilder)localObject).append(String.valueOf(c3).toLowerCase());
    ((StringBuilder)localObject).append(String.valueOf(c4));
    ((StringBuilder)localObject).append(String.valueOf(c14).toLowerCase());
    ((StringBuilder)localObject).append(String.valueOf(c2));
    ((StringBuilder)localObject).append(String.valueOf(c12));
    ((StringBuilder)localObject).append(String.valueOf(c15).toLowerCase());
    ((StringBuilder)localObject).append(String.valueOf(c11).toLowerCase());
    ((StringBuilder)localObject).append(String.valueOf(c10));
    ((StringBuilder)localObject).append(String.valueOf(c1).toLowerCase());
    ((StringBuilder)localObject).append(String.valueOf(c5));
    ((StringBuilder)localObject).append(String.valueOf(c6));
    ((StringBuilder)localObject).append(String.valueOf(c16));
    SecretKeySpec localSecretKeySpec = new SecretKeySpec(((StringBuilder)localObject).toString().getBytes(), g.b());
    localObject = Cipher.getInstance(g.b());
    ((Cipher)localObject).init(2, localSecretKeySpec);
    return new String(((Cipher)localObject).doFinal(Base64.getDecoder().decode(paramString)), "utf-8");
  }
}