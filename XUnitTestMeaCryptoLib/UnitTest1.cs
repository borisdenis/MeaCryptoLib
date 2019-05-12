using System;
using Xunit;

namespace XUnitTestMeaCryptoLib
{
    public class UnitTest1
    {
        [Fact]
        public void TestRijndael()
        {
            MeaCryptoLib.Rijndael CR = new MeaCryptoLib.Rijndael();
            string text = "fdsahsdfhasfhlkjasfljahsfhasdfhk askjdfhasjklhfashflahsdjfhkjlasfjk asjkdfhdhfjaslkafsjkf6546546456456454545/***++++";
            string pass = "44667874465546556464";
            int passwordIterations = 200;
            var cryptres = CR.Encrypt(text, pass, passwordIterations);
            var decryptes = CR.Decrypt(cryptres, pass, passwordIterations);
            bool result = false;
            if (text == decryptes) result = true;
            Assert.True(result);
        }
    }
}
