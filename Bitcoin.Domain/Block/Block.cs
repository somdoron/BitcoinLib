using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bitcoin.Domain.Block
{
    public class Block
    {
        public string Hash { get; private set; }
        public int Version { get; private set; }

    }
}
