var fuzz = require("../fuzz");

fuzz.use_java = true;
fuzz.init_function = function () {

  var MainActivity = Java.use('com.example.ndktest1.MainActivity');
  var JString = Java.use('java.lang.String');
  
  fuzz.target_function = Module.findExportByName(fuzz.target_module, "target_func");

  fuzz.fuzzer_test_one_input = function (payload, size) {

    var str = JString.$new(Java.array('byte', payload.readByteArray(size)));

    fuzz.target_function(str);

  }

};

console.log (" >> Agent loaded!");
