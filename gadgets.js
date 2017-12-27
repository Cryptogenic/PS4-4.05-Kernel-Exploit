/* For storing the gadget and import map */
window.gadgetMap = [];
window.basicImportMap = [];

/* All function stubs / imports from other modules */
var generateBasicImportMap = function()
{
  window.basicImportMap =
  {
    '4.05':
    {
      'setjmp':            getGadget('libSceWebKit2', 0x270),     // setjmp imported from libkernel
      '__stack_chk_fail': getGadget('libSceWebKit2', 0x2728DF8),
    }
  };
}

/* All gadgets from the binary of available modules */
var generateGadgetMap = function()
{
  window.gadgetMap =
  {
    '4.05':
    {
      'pop rsi':  getGadget('libSceWebKit2', 0xA459E),
      'pop rdi':  getGadget('libSceWebKit2', 0x10F1C1),
      'pop rax':  getGadget('libSceWebKit2', 0x1D70B),
      'pop rcx':  getGadget('libSceWebKit2', 0x1FCA9B),
      'pop rdx':  getGadget('libSceWebKit2', 0xD6660),
      'pop r8':   getGadget('libSceWebKit2', 0x4A3B0D),
      'pop r9':   getGadget('libSceWebKit2', 0xEB5F8F),
      'pop rsp':  getGadget('libSceWebKit2', 0x20AEB0),

      'push rax': getGadget('libSceWebKit2', 0x126EFC),

      'add rax, rcx': getGadget('libSceWebKit2', 0x86F06),

      'mov rax, rdi':             getGadget('libSceWebKit2', 0x5863),
      'mov qword ptr [rdi], rax': getGadget('libSceWebKit2', 0x11ADD7),
      'mov qword ptr [rdi], rsi': getGadget('libSceWebKit2', 0x43CF70),

      'mov rax, qword ptr [rax]': getGadget('libSceWebKit2', 0xFD88D),

      'jmp addr': getGadget('libSceWebKit2', 0x852624),

      'infloop': getGadget('libSceWebKit2', 0x45A11),
      'jmp rax': getGadget('libSceWebKit2', 0x1CA2B9),
      'push rax; jmp rcx': getGadget('libSceWebKit2', 0x469B80),

      'ret': getGadget('libSceWebKit2', 0xC8),
      'syscall': getGadget('libSceWebKit2', 0x1C69388),
    }
  };
}
