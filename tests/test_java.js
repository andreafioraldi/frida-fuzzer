var fuzz = require("../fuzz");

// To start the fuzzing loop manually when Java is avaiable
fuzz.manual_loop_start = true;

fuzz.init_callback = function () {

  Java.perform(function () {

    // Find the MainActivity instance
    var activity = null;
    Java.choose('com.example.ndktest1.MainActivity', {
      onMatch: function (instance) {
        activity = instance;
        return "stop";
      },
      onComplete: function () {}
    });
    
    var JString = Java.use('java.lang.String');
    
    // Clone to enable traps: 'all', this is mandatory
    var test_java_func = activity.test_java_func.clone({ traps: 'all' });

    fuzz.fuzzer_test_one_input = function (/* Uint8Array */ payload) {

      var arr = Array.from(payload);
      var str = JString.$new(Java.array('byte', arr));
      
      test_java_func.call(activity, str);

    }

    /* Manually start loop so that we ensure to call fuzzer_test_one_input
       in the Java perform context */
    fuzz.fuzzing_loop();

  });

}

console.log (" >> Agent loaded!");
