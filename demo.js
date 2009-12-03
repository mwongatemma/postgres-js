var sys = require("sys");
var Postgres = require("./postgres");

var db = new Postgres.Connection("dbname", "username", "password");
db.query("SELECT * FROM test");
db.query("SELECT * FROM test", function (data) {
  sys.p(data);
});
db.close();
