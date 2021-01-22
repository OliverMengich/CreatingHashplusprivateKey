using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Akavache;
using System.Reactive.Linq;
namespace HashSign
{
    public class Block
    {
        public readonly DateTime _dateTime;
        private long nonce;
        public string PreviousHash { get; set; }
        public List<Transaction> Transactions { get; set; }
        public string Hash { get; private set; }

        readonly RSACryptoServiceProvider csp = new RSACryptoServiceProvider();
        private RSAParameters _privateKey;
        public Block(DateTime dateTime,List<Transaction> transactions,string previousHash="")
        {

            _privateKey = csp.ExportParameters(true);
            _dateTime = dateTime;
            nonce = 0;
            Transactions = transactions;
            PreviousHash = previousHash;
            Hash = ComputeHash();
        }
        
        public  void MineBlock(int proofOfWorkDifficulty)
        {
            var time = DateTime.Now.Millisecond;
            string hashValidationTemplate = new String('0', proofOfWorkDifficulty);

            while (Hash.Substring(0, proofOfWorkDifficulty) != hashValidationTemplate)
            {
                nonce++;
                Hash = ComputeHash();
            }
            var newtime = DateTime.Now.Millisecond;
            Console.WriteLine("New Nonce is " +nonce + "Elapsed time to mine is "+(newtime-time));
            Console.WriteLine("Blocked with HASH={0} successfully mined!", Hash);
        }
        
        public string ComputeHash()
        {
            string fin = PreviousHash + Transactions + _dateTime + nonce;
            

            SHA256 sha = SHA256.Create();
            var y = sha.ComputeHash(CreateHash(_privateKey, fin));
            return Encoding.Default.GetString(y);
        }
        public byte[] CreateHash(RSAParameters _private, string data)
        {
            
            using (var csp = new RSACryptoServiceProvider())
            {
                csp.ImportParameters(_private);
                byte[] vs = Encoding.UTF8.GetBytes(data);
                return HashSign(_private, vs);
            }
        }
        public byte[] HashSign(RSAParameters _private, byte[] data)
        {
            using (var csp = new RSACryptoServiceProvider())
            {
                var x = csp.SignData(data, SHA256.Create());
                return x;
            }
        }
    }
}
