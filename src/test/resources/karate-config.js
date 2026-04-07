function fn() {
  var port = karate.properties['local.server.port'] || '8080';
  var config = {
    baseUrl: 'http://localhost:' + port
  };
  return config;
}
