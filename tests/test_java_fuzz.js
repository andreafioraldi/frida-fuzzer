var fuzz = require("../fuzz");

// Start the fuzzing loop manually when Java is avaiable
fuzz.manual_loop_start = true;

Java.perform(function () {

  console.log (" >> Java is ready!");

  var MainActivity = Java.use('com.example.ndktest1.MainActivity');
  
  MainActivity.sendMessage.implementation = function () {
  
    console.log (" >> Button clicked!");
  
    var activity = this;
    var JString = Java.use('java.lang.String');
  
    // TODO this is broken, wait Ole for the next Frida release
    fuzz.target_module = Process.findModuleByAddress(activity.test_java_func.handle);
    
    // TODO recreate method with traps: all

    fuzz.fuzzer_test_one_input = function (payload, size) {

      var str = JString.$new(Java.array('byte', payload.readByteArray(size)));

      activity.test_java_func(str);

    }

    /* Manually start loop so that we ensure to call fuzzer_test_one_input
       in the Java perform context */
    fuzz.fuzzing_loop();
  
  }

});

console.log (" >> Agent loaded!");
