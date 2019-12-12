var fuzz = require("../fuzz");

fuzz.use_java = true;
fuzz.init_function = function () {

  var MainActivity = Java.use('com.example.ndktest1.MainActivity');
  
  MainActivity.sendMessage.implementation = function () {
  
    var activity = this;
    var JString = Java.use('java.lang.String');
  
    fuzz.target_module = Process.findModuleByAddress(activity.test_java_func.handle);

    fuzz.fuzzer_test_one_input = function (payload, size) {

      var str = JString.$new(Java.array('byte', payload.readByteArray(size)));

      activity.test_java_func(str);

    }

    fuzz.fuzzing_loop();
  
  }

  return true;

};

console.log (" >> Agent loaded!");
