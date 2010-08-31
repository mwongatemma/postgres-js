var sys = require("sys");
var pg = require("./lib/postgres-pure");
pg.DEBUG=0;

var db = new pg.connect("pgsql://test:12345@localhost:5432/template1");
db.prepare("SELECT ?::int", function (sth) {
    sth.execute([1], function (rs) {
        for (var i = 0; i < rs.length; i++) {
            for (var key in rs[i]) {
                if (rs[i].hasOwnProperty(key)) {
                    sys.puts(key +": " +rs[i][key]);
                }
            }
        }
        db.end();
    });
    sth.execute([2], function (rs) {
        sys.puts(sys.inspect(rs));
    })
});