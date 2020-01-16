var fuzz = require("../fuzz");

fuzz.target_module = "libxml2.so.2";

/* Load libdislocator and hook the PLT of the target module. DO NOT hook the
   symbols in libc otherwise Frida itself will use the dislocator malloc
   and freeze your machine (problably there are memory leaks in the runtime) */ 
/*
var subs = ["malloc", "calloc", "realloc", "free", "memalign", "posix_memalign"];
var disloc = Module.load("/home/andrea/AFLplusplus/libdislocator.so");

Process.enumerateModules().forEach(function (m) {

  if (m.name !== fuzz.target_module) return;
  
  m.enumerateImports().forEach(function (e) {
    if (e.type == "function" && subs.indexOf(e.name) !== -1)
      Interceptor.replace(e.address, disloc.getExportByName(e.name));
  });
  
});
*/

// XML dictionary from AFL
fuzz.dictionary = [" encoding=\"1\"", " a=\"1\"", " href=\"1\"", " standalone=\"no\"", " version=\"1\"", " xml:base=\"1\"", " xml:id=\"1\"", " xml:lang=\"1\"", " xml:space=\"1\"", " xmlns=\"1\"", "&lt;", "&#1;", "&a;", "&#x1;", "ANY", "[]", "CDATA", ":fallback", ":a", ":include", "--", "EMPTY", "\"\"", "''", "ENTITIES", "ENTITY", "#FIXED", "ID", "IDREF", "IDREFS", "#IMPLIED", "NMTOKEN", "NMTOKENS", "NOTATION", "()", "#PCDATA", "%a", "PUBLIC", "#REQUIRED", ":schema", "SYSTEM", "UCS-4", "UTF-16", "UTF-8", "xmlns:", "<!ATTLIST", "<![CDATA[", "</a>", "<!DOCTYPE", "<!ELEMENT", "<!ENTITY", "<![IGNORE[", "<![INCLUDE[", "<!NOTATION", "<a>", "<a />", "<!", "<?", "]]>", "<?xml?>"];

var xmlReadMemory_addr = DebugSymbol.fromName("xmlReadMemory").address;
var xmlReadMemory = new NativeFunction(xmlReadMemory_addr, "pointer",
  ['pointer', 'int', 'pointer', 'pointer', 'int'], { traps: 'all' });

// don't trace xmlFreeDoc
var xmlFreeDoc_addr = DebugSymbol.fromName("xmlFreeDoc").address;
var xmlFreeDoc = new NativeFunction(xmlFreeDoc_addr, "void", ["pointer"]);

var name = Memory.allocUtf8String("noname.xml");

fuzz.fuzzer_test_one_input = function (/* Uint8Array */ payload) {

  var payload_mem = payload.buffer.unwrap();

  var r = xmlReadMemory(payload_mem, payload.length, name, ptr(0), 0);
  if (!r.isNull())
    xmlFreeDoc(r);

}

console.log (" >> Agent loaded!");
