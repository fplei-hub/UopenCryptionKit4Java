package com.uopen.cryptionkit.key;

/**
 * @author fplei
 * @create 2020-05-30-19:02
 */
public class KeyCreatorDefault extends KeyCreator {
    public static KeyCreatorDefault DEFAULT() {
        return new KeyCreatorDefault();
    }

    @Override
    public String getAesPass() {
        return "my2020aes!@#_121872";
    }

    @Override
    public String getDesPass() {
        return "18272hak";
    }

    @Override
    public String getTriplePass() {
        return "my2020des$#_!1234567890";
    }

    @Override
    public String getRsaPrivatePass() {
        return "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCFKHC4jBwPDyGzCYGsqUaGcNCc139qIbmNrkGMaqnKOKF3h3sbx1iqz3gqlYLh+XWoyWW3C5RTykTdnUCe4farGXE2Vo4BtP1AdnzqMdrojLmuAaH2isDMZcmzr/vWNRQDu0kJ2T14txZ2Hu9nNhf87YQGaxjd7jUVmqbAhcxkkSffRGcjXfIhrBLPdEm6FvXD6vUS8H4W2tobQLIZOZo1h1uc9DmnpVsZWk9kU/ndmwcw7ofvlU/A9pEF2zadk2yxI6PbCjy93sAYJuoZaAaIq7hP+mkCEW6z+eiMDkc7AyLrhCJpM2tnwfEOfHWUPRVsolLvPguQNw0QF5rI52wlAgMBAAECggEASu28sDw3Ncof/m0lCRGf29rzqK4ixof/r9gUjn0e2eoQAgC8p57/J+7jAaNsKNiE+tuJXv0nFBdHtSTdzgn9Eb6ZVChUdGVx9Ko4FFjFhAJcIaxNhTwCzYGhhHlMzvbDMm5a5S3XR2xPOVyi/oMT8IF+v1XYglmeiW+i0cb4gsXTrTeytgNJOIj5DzZhq4VM2Wedi/259n0MykE3miE9NW4io2Ozk4lA8dxhjCJgSpDg3gi2CF9eVCVePBTK2PbS5OMNd1FwW7ns9Ac2Au9jhQTrcSFzGbd0VXuyyjkYizeyWvSSFbZpcG/a4vtn1NwhbD/Z59owFt50OUmjXslB6QKBgQC/PheurpUxzlTodMFzaVtoaWsSLbT+texcNYg0dlKYF9jP5buRJK4QynFTYfopIaMNNOWlohzNx0jDpjR1L8qy/E9ZC+TN3Bu7emNtAdWfWtxQV3x/29vyQJdeiUtD92QYN6orVG8om/G8qhg33HftcOFl4N/mYOMldtYPrvK29wKBgQCyP0WSnIhymzbxw200Z8JBYKIE/w+cnbUBNqJjmF9s6v9OaLF3fmuXCQZPixdS4vk3UOTwWGa7WIUe39Fbose2gFJheoFi9i7AC5+gghdV5BlY2d9Nfe+Gt9S3UEZYsBefvRdrs5d9/XAwtQoaXkpeFdF11u4JE7y7duUhI4DiwwKBgEhGbyzVTg1ErVIsze+QIbuUG6MDIyQgHPO8R32MOirA2G+5oul3s1ElMS8SGDjzPWwAUcoHOluKtTU72xduuGxsbpB4rkAer1xrJKhNyS4waJL0fVjU/orPXmWb/ZXyKSH955H4lwoB5Zonrn9uEuTphEW8duHaO/4sqznCJHiBAoGAYx92dCKiaoFQW7/e0d7Fkw/G6dphdynoh4U3ZwVMQ8inM5Za4mWmNTaqkL97t/dKue09cz7l2ldOqC21Qi1SvHW92kGDBGJ8+wU7vsm5amVPhy6Z1IEtG5DNNSfqBtXePVGtXZJgs4qlwiBbPvCikJG3ir18YAXe1a03nGce/HsCgYEArK2zX+t25C4n+AACXJNh85uTCALxlJfqrzopdjaAVYPXJHPFvhGaqLL91T5j1MXKdBOWOBlrg4ZBTPv1/fsPUI0mqmxBnM04aBd7r1QVWVqI132r33zLLZU0d7iByEruMxNSNp9MzGJm8F8PJxGccGksoNyb3ENgdRxg3pyNgNU\\=";
    }

    @Override
    public String getRsaPublicPass() {
        return "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhShwuIwcDw8hswmBrKlGhnDQnNd/aiG5ja5BjGqpyjihd4d7G8dYqs94KpWC4fl1qMlltwuUU8pE3Z1AnuH2qxlxNlaOAbT9QHZ86jHa6Iy5rgGh9orAzGXJs6/71jUUA7tJCdk9eLcWdh7vZzYX/O2EBmsY3e41FZqmwIXMZJEn30RnI13yIawSz3RJuhb1w+r1EvB+FtraG0CyGTmaNYdbnPQ5p6VbGVpPZFP53ZsHMO6H75VPwPaRBds2nZNssSOj2wo8vd7AGCbqGWgGiKu4T/ppAhFus/nojA5HOwMi64QiaTNrZ8HxDnx1lD0VbKJS7z4LkDcNEBeayOdsJQIDAQAB";
    }

    @Override
    public String getHmacShaPass() {
        return "bilibili1219832020";
    }

    @Override
    public String getSm2PublicPass() {
        return "0475658556b7ebff57a95b4da1cfefdb131f22909e2cd3265ace57d67a8033d522d40173db64a78a21d68035148694e01ffd973fb1c1af471c016e59c60c01fc0c";
    }

    @Override
    public String getSm2PrivatePass() {
        return "1eadfb948c582c03819d130837de5a6dcb9d8f6101ea1cf05982c27fb75027a5";
    }

    @Override
    public String getSm4Pass() {
        return "JeF8U9wHFOMfs2Y8";
    }

    @Override
    public String getDasPrivateKey() {
        return "MIIBSwIBADCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoEFgIUBiCZo7Aw+lPTaXf8an2bdqMVCMo=";
    }

    @Override
    public String getDasPublicKey() {
        return "MIIBtzCCASwGByqGSM44BAEwggEfAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9EAMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv8iIDGZ3RSAHHAhUAl2BQjxUjC8yykrmCouuEC/BYHPUCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoDgYQAAoGASIyEgiooFat7lb8fIuTir5JyvxDHBZIbwcvFewZ2eb8Fv7VW+z84CsjNswNOu1f81palcFA8vDyp2bv2tP+3OAAEnWbjYJQDNTc29ZZk3r0SwnPlmlFqLXUmBF8ROce991WEI0khGLwTNlNSMynhLljFZnW1fGplKzWMFetL7DQ=";
    }
}
