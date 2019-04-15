module.exports = function(grunt) {

  // Project configuration.
  grunt.initConfig({
    pkg: grunt.file.readJSON('package.json'),
    minified : {
      files: {
        src: [
        /*'js_src/config.js',
        'js_src/curve.js',
        'js_src/utils.js',
        'js_src/scalar.js',
        'js_src/group-element.js',
        'js_src/private-key.js',
        'js_src/public-key.js',
        'js_src/re-encryption-key.js',
        'js_src/key-pair.js',
        'js_src/capsule.js',*/
        'js_src/proxy.js',
        'js_src/ext/elliptic.js',
        'js_src/ext/bn.js',
        'js_src/ext/sha256.js',
        ],
        dest: 'js_src/proxy-'
      },
      options : {
        allinone: true
      }
    }
  });

  // Load the plugin that provides the "uglify" task.
  grunt.loadNpmTasks('grunt-minified');

  // Default task(s).
  grunt.registerTask('default', ['minified']);

};
