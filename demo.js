var sys = require("sys");
var pg = require("./lib/postgres-pure");
pg.DEBUG=true;

var db = new pg.connect("pgsql://aurynn:12345@localhost:5432/akhyana");
db.prepare("SELECT * FROM users where id = $1;", function (sth) {
    sth.execute([1], function (rs) {
        for (var i = 0; i <= rs.length; i++) {
            sys.puts(rs[i]);
        }
    });
});