using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HashSign
{
    class Blockchain
    {
        public List<Transaction> _unMinedTransaction;
        private readonly int _proofOfWorkDifficulty;
        private readonly double _minerReward;
        public List<Block> Chain { get; set; }
        public Blockchain(int proofOfWorkDifficulty,int minerReward)
        {
            _proofOfWorkDifficulty = proofOfWorkDifficulty;
            _minerReward = minerReward;
            _unMinedTransaction = new List<Transaction>();
            Chain = new List<Block> { CreateGenesisBlock() };
        }
        public void CreateTransaction(Transaction transaction)
        {
            _unMinedTransaction.Add(transaction);
        }
        private Block CreateGenesisBlock()
        {
            var transactions = new List<Transaction> { new Transaction("", "", 0) };
            return new Block(DateTime.Now, transactions, "0");
        }
        public void MineBlock(string minerAddress)
        {
            Transaction minerRewardTransaction = new Transaction(null, minerAddress, _minerReward);
            _unMinedTransaction.Add(minerRewardTransaction);
            Block block = new Block(DateTime.Now, _unMinedTransaction);
            block.MineBlock(_proofOfWorkDifficulty);

            block.PreviousHash = Chain.Last().Hash;
            Chain.Add(block);

            _unMinedTransaction = new List<Transaction>();
        }
        public double GetBalance(string address)
        {
            double balance = 0;
            foreach (Block block in Chain)
            {
                foreach (Transaction transaction in block.Transactions)
                {
                    if (transaction.From == address)
                    {
                        balance -= transaction.Amount;
                    }
                    if (transaction.To == address)
                    {
                        balance += transaction.Amount;
                    }
                }
            }
            return balance;
        }
        public bool IsValidChain()
        {
            for (int i = 1; i < Chain.Count; i++)
            {
                Block previousBlock = Chain[i - 1];
                Block currentBlock = Chain[i];
                if (currentBlock.Hash != currentBlock.ComputeHash())
                    return false;
                if (currentBlock.PreviousHash != previousBlock.Hash)
                    return false;
            }
            return true;
        }
    }
}
