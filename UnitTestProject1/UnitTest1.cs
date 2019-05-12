using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace UnitTestProject1
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestRijndael()
        {

            MeaCryptoLib.Rijndael CR = new MeaCryptoLib.Rijndael();
            string text = "fdsahsdfhasfhlkjasfljahsfhasdfhk askjdfhasjklhfashflahsdjfhkjlasfjk asjkdfhdhfjaslkafsjkf6546546456456454545/***++++";
            string pass = "44667874465546556464";
            int passwordIterations = 20;
            string cryptres = CR.Encrypt(text, pass, passwordIterations);
            string decryptes = CR.Decrypt(cryptres, pass, passwordIterations);
            string decryptes2 = CR.Decrypt(cryptres, pass, passwordIterations+1);
            string decryptes3 = CR.Decrypt(cryptres, pass+"2", passwordIterations);
            string decryptesFail = CR.Decrypt(cryptres, pass, passwordIterations+1);

            Assert.AreEqual(text, decryptes);
            Assert.AreNotEqual(text, decryptesFail);
            Assert.AreNotEqual(text, cryptres);
            Assert.AreNotEqual(text, decryptesFail);
            Assert.AreNotEqual(decryptes, decryptes2);
            Assert.AreNotEqual(decryptes, decryptes3);
        }

        [TestMethod]
        public void TestBase64()
        {
            string text = "fdsahsdfhasfhlkjasfljahsfhasdfhk askjdfhasjklhfashflahsdjfhkjlasfjk asjkdfhdhfjaslkafsjkf6546546456456454545/***++++";
            MeaCryptoLib.Base64 CR = new MeaCryptoLib.Base64();
            string cryptres = CR.Encrypt(text);
            string decryptes = CR.Decrypt(cryptres);

            Assert.AreEqual(text, decryptes);
            Assert.AreNotEqual(decryptes, cryptres);
        }
    }
}
