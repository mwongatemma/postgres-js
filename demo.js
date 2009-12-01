var sys = require("sys");
var Postgres = require("./postgres");

var db = new Postgres.Connection("database", "username", "password");
db.query("SELECT * FROM sometable", function (data) {
  sys.p(data);
});
db.close();
