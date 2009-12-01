var sys = require("sys");
var Postgres = require("./postgres");
Postgres.DEBUG = 1;

var db = new Postgres.Connection("database", "username", "password");
db.query("SELECT * FROM sometable", function (data) {
  sys.p(data);
});
db.close();
